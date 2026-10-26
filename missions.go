package main

// Data Sync missions (Marti /Marti/api/missions, as in TAK Server and OpenTAKServer): shared map items
// and files a team subscribes to. ATAK's Data Sync, WebTAK and other clients list, subscribe, read the
// mission's CoT and files; CoT sent with <marti><dest mission="…"/></marti> is added to the mission and
// delivered to its subscribers.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const maxMissionChanges = 2000

func martiTime(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func findMission(st *State, name string) *Mission {
	for _, m := range st.Missions {
		if strings.EqualFold(m.Name, name) {
			return m
		}
	}
	return nil
}

// normalize: missions created by older versions or through the OTS API get the Data Sync fields.
func normalizeMission(m *Mission) {
	if m.GUID == "" {
		m.GUID = newUUID()
	}
	if m.CoT == nil {
		m.CoT = map[string]string{}
	}
	if m.Tool == "" {
		m.Tool = "public"
	}
	if m.Password != "" && m.PassHash == "" {
		m.PassHash, m.Password = hashPassword(m.Password), ""
	}
	for _, u := range m.UIDs {
		m.Items = append(m.Items, &MissionItem{UID: u, Time: m.Created})
	}
	for _, h := range m.Contents {
		m.Files = append(m.Files, &MissionFile{Hash: h, Time: m.Created})
	}
	m.UIDs, m.Contents = nil, nil
}

func (m *Mission) addChange(c *MissionChange) {
	m.Changes = append(m.Changes, c)
	if len(m.Changes) > maxMissionChanges {
		m.Changes = m.Changes[len(m.Changes)-maxMissionChanges:]
	}
}

// missionVisible: missions with groups are only shown to members of one of them (like OTS / TAK Server).
// Must be called with the state locked: reads the user's groups from st.
func missionVisible(st *State, m *Mission, id *identity) bool {
	if len(m.Groups) == 0 || (id != nil && id.Admin) {
		return true
	}
	if id == nil || id.User == "" || id.Via == "anon" {
		return false
	}
	u := findUser(st, id.User)
	if u == nil {
		return false
	}
	var gs []string
	for _, mb := range u.Groups {
		gs = append(gs, mb.Group)
	}
	return intersects(m.Groups, gs)
}

// missionJSON must be called with the state locked.
func (s *Server) missionJSON(st *State, m *Mission) map[string]any {
	uids := []map[string]any{}
	for _, it := range m.Items {
		d := map[string]any{"type": it.Type, "callsign": it.Callsign, "iconsetPath": "", "color": ""}
		if it.Lat != 0 || it.Lon != 0 {
			d["location"] = map[string]any{"lat": it.Lat, "lon": it.Lon}
		}
		uids = append(uids, map[string]any{"data": it.UID, "creatorUid": it.CreatorUID, "timestamp": martiTime(it.Time), "details": d})
	}
	contents := []map[string]any{}
	for _, f := range m.Files {
		if pk := st.Packages[f.Hash]; pk != nil {
			contents = append(contents, map[string]any{"data": s.resourceJSON(pk), "creatorUid": f.CreatorUID, "timestamp": martiTime(f.Time)})
		}
	}
	groups := m.Groups
	if groups == nil {
		groups = []string{}
	}
	kw := m.Keywords
	if kw == nil {
		kw = []string{}
	}
	return map[string]any{
		"name": m.Name, "description": m.Description, "chatRoom": m.ChatRoom, "baseLayer": "", "bbox": "", "path": "", "classification": "",
		"tool": m.Tool, "keywords": kw, "creatorUid": m.CreatorUID, "createTime": martiTime(m.Created), "externalData": []any{},
		"feeds": []any{}, "mapLayers": []any{}, "defaultRole": map[string]any{"type": orDefault(m.DefaultRole, "MISSION_SUBSCRIBER")},
		"inviteOnly": false, "expiration": -1, "guid": m.GUID, "uids": uids, "contents": contents, "passwordProtected": m.PassHash != "",
		"groups": groups,
	}
}

// resourceJSON: a file in the format TAK Server uses inside missions.
func (s *Server) resourceJSON(pk *Package) map[string]any {
	kw := pk.Keywords
	if kw == nil {
		kw = []string{}
	}
	return map[string]any{"filename": pk.Name, "name": pk.Name, "keywords": kw, "mimeType": pk.MIME, "hash": pk.Hash, "uid": pk.Hash,
		"submissionTime": martiTime(pk.Submitted), "submitter": pk.User, "creatorUid": pk.CreatorUID, "size": pk.Size, "tool": pk.Tool}
}

func missionEnvelope(typ string, data any) map[string]any {
	return map[string]any{"version": "3", "type": typ, "data": data, "nodeId": ""}
}

// handleMissions serves /Marti/api/missions and /Marti/api/missions/{name}/…
func (s *Server) handleMissions(w http.ResponseWriter, r *http.Request, id *identity) {
	rest := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/Marti/api/missions"), "/")
	q := r.URL.Query()
	if rest == "" {
		var data []map[string]any
		s.store.Update(func(st *State) {
			for _, m := range st.Missions {
				normalizeMission(m)
				if !missionVisible(st, m, id) || m.Tool == "vbm" {
					continue
				}
				if t := q.Get("tool"); t != "" && m.Tool != t {
					continue
				}
				data = append(data, s.missionJSON(st, m))
			}
		})
		if data == nil {
			data = []map[string]any{}
		}
		writeJSON(w, 200, missionEnvelope("Mission", data))
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	name, _ := url.PathUnescape(parts[0])
	sub := ""
	if len(parts) == 2 {
		sub = strings.Trim(parts[1], "/")
	}
	if name == "all" && sub == "invitations" {
		writeJSON(w, 200, missionEnvelope("MissionInvitation", []any{}))
		return
	}
	clientUID := orDefault(q.Get("uid"), orDefault(q.Get("clientUid"), q.Get("creatorUid")))

	// create
	if sub == "" && r.Method == http.MethodPut {
		if strings.TrimSpace(name) == "" || len(name) > 200 {
			jsonErr(w, 400, "mission name missing")
			return
		}
		status := 200
		var out map[string]any
		s.store.Update(func(st *State) {
			m := findMission(st, name)
			if m == nil {
				status = 201
				m = &Mission{Name: name, CreatorUID: q.Get("creatorUid"), Created: time.Now(), Tool: orDefault(q.Get("tool"), "public")}
				if pw := q.Get("password"); pw != "" {
					m.PassHash = hashPassword(pw)
				}
				st.Missions = append(st.Missions, m)
				normalizeMission(m)
				m.addChange(&MissionChange{Type: "CREATE_MISSION", Time: time.Now(), CreatorUID: m.CreatorUID})
			}
			if d := q.Get("description"); d != "" {
				m.Description = d
			}
			if c := q.Get("chatRoom"); c != "" {
				m.ChatRoom = c
			}
			if g := q["group"]; len(g) > 0 {
				m.Groups = g
			}
			if dr := q.Get("defaultRole"); dr != "" {
				m.DefaultRole = dr
			}
			out = s.missionJSON(st, m)
		})
		writeJSON(w, status, missionEnvelope("Mission", []any{out}))
		return
	}

	var m *Mission
	var visible bool
	s.store.Update(func(st *State) {
		if m = findMission(st, name); m != nil {
			normalizeMission(m)
			visible = missionVisible(st, m, id)
		}
	})
	if m == nil || !visible {
		jsonErr(w, 404, "mission not found")
		return
	}
	// subscribers get a token; reading with it (or with the password) is allowed for protected missions
	authorized := func() bool {
		if id != nil && id.Admin {
			return true
		}
		ok := true
		s.store.Read(func(st *State) {
			if m.PassHash == "" {
				return
			}
			ok = checkPassword(m.PassHash, q.Get("password"))
			if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); !ok && tok != "" {
				for _, sb := range m.Subs {
					ok = ok || sb.Token == tok
				}
			}
		})
		return ok
	}

	switch {
	case sub == "" && r.Method == http.MethodGet:
		if !authorized() {
			jsonErr(w, 401, "mission is password protected")
			return
		}
		var out map[string]any
		s.store.Read(func(st *State) { out = s.missionJSON(st, m) })
		writeJSON(w, 200, missionEnvelope("Mission", []any{out}))
	case sub == "" && r.Method == http.MethodDelete:
		if id == nil || (!id.Admin && m.CreatorUID != q.Get("creatorUid")) {
			jsonErr(w, 403, "only the creator or an administrator can delete a mission")
			return
		}
		s.store.Update(func(st *State) {
			keep := st.Missions[:0]
			for _, x := range st.Missions {
				if x != m {
					keep = append(keep, x)
				}
			}
			st.Missions = keep
		})
		writeJSON(w, 200, missionEnvelope("Mission", []any{}))
	case sub == "subscription" && r.Method == http.MethodPut:
		if m.PassHash != "" && !checkPassword(m.PassHash, q.Get("password")) && (id == nil || !id.Admin) {
			jsonErr(w, 401, "wrong mission password")
			return
		}
		if clientUID == "" {
			jsonErr(w, 400, "uid missing")
			return
		}
		user := ""
		if id != nil {
			user = id.User
		}
		var sb *MissionSub
		s.store.Update(func(st *State) {
			for _, x := range m.Subs {
				if x.ClientUID == clientUID {
					sb = x
				}
			}
			if sb == nil {
				sb = &MissionSub{ClientUID: clientUID, Token: randomHex(24)}
				m.Subs = append(m.Subs, sb)
			}
			sb.Username, sb.Time = user, time.Now()
		})
		writeJSON(w, 201, missionEnvelope("com.bbn.marti.sync.model.MissionSubscription", map[string]any{
			"token": sb.Token, "clientUid": sb.ClientUID, "username": sb.Username, "createTime": martiTime(sb.Time),
			"role": map[string]any{"type": orDefault(m.DefaultRole, "MISSION_SUBSCRIBER"),
				"permissions": []string{"MISSION_READ", "MISSION_WRITE"}},
		}))
	case sub == "subscription" && r.Method == http.MethodDelete:
		s.store.Update(func(st *State) {
			keep := m.Subs[:0]
			for _, x := range m.Subs {
				if x.ClientUID != clientUID {
					keep = append(keep, x)
				}
			}
			m.Subs = keep
		})
		w.WriteHeader(200)
	case sub == "subscriptions" && r.Method == http.MethodGet:
		var uids []string
		s.store.Read(func(st *State) {
			for _, x := range m.Subs {
				uids = append(uids, x.ClientUID)
			}
		})
		if uids == nil {
			uids = []string{}
		}
		writeJSON(w, 200, missionEnvelope("MissionSubscription", uids))
	case sub == "cot" && r.Method == http.MethodGet:
		if !authorized() {
			jsonErr(w, 401, "mission is password protected")
			return
		}
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><events>`)
		s.store.Read(func(st *State) {
			for _, it := range m.Items {
				if raw := m.CoT[it.UID]; raw != "" {
					b.WriteString(stripXMLDecl(raw))
				}
			}
		})
		b.WriteString(`</events>`)
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, b.String())
	case sub == "contents" && r.Method == http.MethodPut:
		var body struct {
			Hashes []string `json:"hashes"`
			UIDs   []string `json:"uids"`
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)
		creator := q.Get("creatorUid")
		var out map[string]any
		var added []*MissionChange
		s.store.Update(func(st *State) {
			for _, h := range body.Hashes {
				h = strings.ToLower(h)
				if st.Packages[h] == nil || hasFile(m, h) {
					continue
				}
				m.Files = append(m.Files, &MissionFile{Hash: h, CreatorUID: creator, Time: time.Now()})
				c := &MissionChange{Type: "ADD_CONTENT", Time: time.Now(), CreatorUID: creator, Hash: h}
				m.addChange(c)
				added = append(added, c)
			}
			for _, u := range body.UIDs {
				if u == "" || hasItem(m, u) {
					continue
				}
				m.Items = append(m.Items, &MissionItem{UID: u, CreatorUID: creator, Time: time.Now()})
				c := &MissionChange{Type: "ADD_CONTENT", Time: time.Now(), CreatorUID: creator, UID: u}
				m.addChange(c)
				added = append(added, c)
			}
			out = s.missionJSON(st, m)
		})
		for _, c := range added {
			s.notifyMission(m, c)
		}
		writeJSON(w, 200, missionEnvelope("Mission", []any{out}))
	case sub == "contents" && r.Method == http.MethodDelete:
		creator := q.Get("creatorUid")
		var removed []*MissionChange
		s.store.Update(func(st *State) {
			if h := strings.ToLower(q.Get("hash")); h != "" {
				keep := m.Files[:0]
				for _, f := range m.Files {
					if f.Hash == h {
						c := &MissionChange{Type: "REMOVE_CONTENT", Time: time.Now(), CreatorUID: creator, Hash: h}
						m.addChange(c)
						removed = append(removed, c)
						continue
					}
					keep = append(keep, f)
				}
				m.Files = keep
			}
			if u := q.Get("uid"); u != "" {
				keep := m.Items[:0]
				for _, it := range m.Items {
					if it.UID == u {
						c := &MissionChange{Type: "REMOVE_CONTENT", Time: time.Now(), CreatorUID: creator, UID: u}
						m.addChange(c)
						removed = append(removed, c)
						continue
					}
					keep = append(keep, it)
				}
				m.Items = keep
				delete(m.CoT, u)
			}
		})
		for _, c := range removed {
			s.notifyMission(m, c)
		}
		var out map[string]any
		s.store.Read(func(st *State) { out = s.missionJSON(st, m) })
		writeJSON(w, 200, missionEnvelope("Mission", []any{out}))
	case sub == "changes" && r.Method == http.MethodGet:
		var since time.Time
		if sa := atoiDefault(q.Get("secago"), 0); sa > 0 {
			since = time.Now().Add(-time.Duration(sa) * time.Second)
		}
		var data []map[string]any
		s.store.Read(func(st *State) {
			for _, c := range m.Changes {
				if c.Time.Before(since) {
					continue
				}
				data = append(data, s.changeJSON(st, m, c))
			}
		})
		if data == nil {
			data = []map[string]any{}
		}
		writeJSON(w, 200, missionEnvelope("MissionChange", data))
	case sub == "log" || sub == "keywords" || sub == "externaldata":
		writeJSON(w, 200, missionEnvelope("Mission", []any{}))
	default:
		http.NotFound(w, r)
	}
}

func hasFile(m *Mission, h string) bool {
	for _, f := range m.Files {
		if f.Hash == h {
			return true
		}
	}
	return false
}

func hasItem(m *Mission, uid string) bool {
	for _, it := range m.Items {
		if it.UID == uid {
			return true
		}
	}
	return false
}

func stripXMLDecl(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "<?xml") {
		if i := strings.Index(raw, "?>"); i >= 0 {
			return strings.TrimSpace(raw[i+2:])
		}
	}
	return raw
}

func (s *Server) changeJSON(st *State, m *Mission, c *MissionChange) map[string]any {
	out := map[string]any{"type": c.Type, "missionName": m.Name, "timestamp": martiTime(c.Time), "serverTime": martiTime(c.Time),
		"creatorUid": c.CreatorUID, "isFederatedChange": false}
	if c.UID != "" {
		out["contentUid"] = c.UID
		for _, it := range m.Items {
			if it.UID == c.UID {
				out["details"] = map[string]any{"type": it.Type, "callsign": it.Callsign, "color": "", "location": map[string]any{"lat": it.Lat, "lon": it.Lon}}
			}
		}
	}
	if c.Hash != "" {
		if pk := st.Packages[c.Hash]; pk != nil {
			out["contentResource"] = s.resourceJSON(pk)
		}
	}
	return out
}

// missionCoT handles CoT sent to a mission: the item is added/updated and the event goes to every
// connected subscriber. Returns true if the event had a mission destination.
func (s *Server) missionCoT(raw []byte, ev *Event, from *Client) bool {
	if ev.Detail.Marti == nil {
		return false
	}
	var names []string
	for _, d := range ev.Detail.Marti.Dest {
		if d.Mission != "" {
			names = append(names, d.Mission)
		}
	}
	if len(names) == 0 {
		return false
	}
	creator := ""
	if from != nil {
		from.mu.RLock()
		creator = from.UID
		from.mu.RUnlock()
	}
	deleted := ev.Type == "t-x-d-d"
	targetUID := ev.UID
	if deleted {
		for _, l := range ev.Detail.Link {
			targetUID = l.UID
		}
	}
	for _, name := range names {
		var m *Mission
		var change *MissionChange
		var subs []string
		s.store.Update(func(st *State) {
			if m = findMission(st, name); m == nil {
				return
			}
			normalizeMission(m)
			if deleted {
				if hasItem(m, targetUID) {
					keep := m.Items[:0]
					for _, it := range m.Items {
						if it.UID != targetUID {
							keep = append(keep, it)
						}
					}
					m.Items = keep
					delete(m.CoT, targetUID)
					change = &MissionChange{Type: "REMOVE_CONTENT", Time: time.Now(), CreatorUID: creator, UID: targetUID}
				}
			} else {
				var it *MissionItem
				for _, x := range m.Items {
					if x.UID == ev.UID {
						it = x
					}
				}
				if it == nil {
					it = &MissionItem{UID: ev.UID, CreatorUID: creator}
					m.Items = append(m.Items, it)
					change = &MissionChange{Type: "ADD_CONTENT", Time: time.Now(), CreatorUID: creator, UID: ev.UID}
				}
				it.Time, it.Type, it.Callsign, it.Lat, it.Lon = time.Now(), ev.Type, ev.Callsign(), ev.Point.Lat, ev.Point.Lon
				m.CoT[ev.UID] = string(raw)
			}
			if change != nil {
				m.addChange(change)
			}
			for _, sb := range m.Subs {
				subs = append(subs, sb.ClientUID)
			}
		})
		if m == nil {
			continue
		}
		for _, c := range s.hub.Clients() {
			c.mu.RLock()
			uid := c.UID
			c.mu.RUnlock()
			if c != from && uid != "" && contains(subs, uid) {
				c.Send(s.hub.forClient(raw, ev, c))
			}
		}
		if change != nil {
			s.notifyMission(m, change)
		}
	}
	return true
}

// notifyMission sends a mission change notice (t-x-m-c) to connected subscribers, so ATAK reloads it.
func (s *Server) notifyMission(m *Mission, c *MissionChange) {
	var subs []string
	var tool, name string
	s.store.Read(func(st *State) {
		for _, sb := range m.Subs {
			subs = append(subs, sb.ClientUID)
		}
		tool, name = m.Tool, m.Name
	})
	if len(subs) == 0 {
		return
	}
	now := time.Now()
	content := ""
	if c.UID != "" {
		content = "<contentUid>" + xmlEscape(c.UID) + "</contentUid>"
	}
	if c.Hash != "" {
		content = "<contentResource><hash>" + c.Hash + "</hash></contentResource>"
	}
	raw := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><event version="2.0" uid="%s" type="t-x-m-c" how="h-g-i-g-o" time="%s" start="%s" stale="%s"><point lat="0.0" lon="0.0" hae="0.0" ce="9999999" le="9999999"/><detail><mission type="CHANGE" tool="%s" name="%s" authorUid="%s"><MissionChanges><MissionChange>%s<creatorUid>%s</creatorUid><isFederatedChange>false</isFederatedChange><missionName>%s</missionName><timestamp>%s</timestamp><type>%s</type></MissionChange></MissionChanges></mission></detail></event>`,
		newUUID(), cotTime(now), cotTime(now), cotTime(now.Add(20*time.Second)), xmlEscape(tool), xmlEscape(name), xmlEscape(c.CreatorUID),
		content, xmlEscape(c.CreatorUID), xmlEscape(name), martiTime(c.Time), c.Type))
	for _, cl := range s.hub.Clients() {
		cl.mu.RLock()
		uid := cl.UID
		cl.mu.RUnlock()
		if uid != "" && contains(subs, uid) {
			cl.Send(raw)
		}
	}
}

// otsMissionJSON: mission in the format of the OTS web API (/api/missions).
func (s *Server) otsMissionJSON(m *Mission) map[string]any {
	uids := make([]string, 0, len(m.Items))
	for _, it := range m.Items {
		uids = append(uids, it.UID)
	}
	contents := make([]string, 0, len(m.Files))
	for _, f := range m.Files {
		contents = append(contents, f.Hash)
	}
	sort.Strings(uids)
	return map[string]any{"name": m.Name, "description": m.Description, "creator_uid": m.CreatorUID, "create_time": otsTime(m.Created),
		"password_protected": m.PassHash != "", "groups": m.Groups, "tool": m.Tool, "default_role": m.DefaultRole,
		"uids": uids, "contents": contents, "guid": m.GUID}
}
