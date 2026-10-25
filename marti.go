package main

// Marti API: the HTTP interface ATAK, iTAK and WinTAK use (certificate enrollment, data packages,
// contacts, video, version). Paths and formats follow TAK Server / OpenTAKServer.

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleMarti(w http.ResponseWriter, r *http.Request, mode string) {
	p := strings.TrimSuffix(r.URL.Path, "/")
	q := r.URL.Query()
	id := s.who(r)

	// ----- enrollment (port 8446, basic auth with password or QR token) -----
	if strings.HasPrefix(p, "/Marti/api/tls/") {
		if id == nil || (id.Via != "basic" && id.Via != "cert") {
			w.Header().Set("WWW-Authenticate", `Basic realm="TAK"`)
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		switch {
		case p == "/Marti/api/tls/config":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns2:certificateConfig xmlns="http://bbn.com/marti/xml/config" xmlns:ns2="com.bbn.marti.config"><nameEntries><nameEntry name="O" value="WebTAK"/><nameEntry name="OU" value="TAK"/></nameEntries></ns2:certificateConfig>`)
		case strings.HasPrefix(p, "/Marti/api/tls/signClient") && r.Method == http.MethodPost:
			s.signClient(w, r, id.User, strings.HasSuffix(p, "/v2"))
		default:
			http.NotFound(w, r)
		}
		return
	}

	// everything else: client certificate, login, or anonymous on plain HTTP if allowed
	if id == nil {
		cfg := s.store.Config()
		if mode == "http" && cfg.AnonHTTP {
			id = &identity{User: "anonymous", Via: "anon"}
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="TAK"`)
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
	}

	switch {
	case p == "/Marti/api/version":
		fmt.Fprintf(w, "WebTAK-Server %s", Version)
	case p == "/Marti/api/version/config":
		writeJSON(w, 200, map[string]any{"version": "3", "type": "ServerConfig", "nodeId": s.store.Config().ServerUID,
			"data": map[string]any{"version": "WebTAK-Server " + Version, "api": "3", "hostname": clientHost(r)}})
	case p == "/Marti/api/clientEndPoints":
		s.martiClientEndpoints(w, r)
	case p == "/Marti/api/groups/all" || p == "/Marti/api/groups":
		s.martiGroups(w, id)
	case p == "/Marti/api/device/profile/connection" || p == "/Marti/api/device/profile/enrollment":
		s.deviceProfile(w, r, q.Get("clientUid"), strings.HasSuffix(p, "enrollment"))
	case p == "/Marti/sync/missionupload" || p == "/Marti/sync/upload":
		s.martiUpload(w, r, id, p == "/Marti/sync/missionupload")
	case p == "/Marti/sync/missionquery":
		if s.packages.Has(q.Get("hash")) {
			fmt.Fprint(w, s.contentURL(r, q.Get("hash")))
		} else {
			http.NotFound(w, r)
		}
	case p == "/Marti/sync/content":
		s.martiDownload(w, r, q.Get("hash"))
	case strings.HasPrefix(p, "/Marti/api/files/"):
		s.martiDownload(w, r, strings.TrimPrefix(p, "/Marti/api/files/"))
	case strings.HasPrefix(p, "/Marti/api/sync/metadata/") && strings.HasSuffix(p, "/tool"):
		hash := strings.TrimSuffix(strings.TrimPrefix(p, "/Marti/api/sync/metadata/"), "/tool")
		body, _ := io.ReadAll(io.LimitReader(r.Body, 100))
		tool := strings.TrimSpace(string(body))
		if tool == "" {
			tool = "public"
		}
		s.store.Update(func(st *State) {
			if pk := st.Packages[strings.ToLower(hash)]; pk != nil {
				pk.Tool = tool
			}
		})
		w.WriteHeader(200)
	case p == "/Marti/sync/search":
		s.martiSearch(w, r)
	case p == "/Marti/vcm":
		s.martiVideo(w, r)
	case p == "/Marti/api/missions":
		s.martiMissions(w)
	case p == "/Marti/api/citrap" || p == "/Marti/api/contacts/all":
		writeJSON(w, 200, []any{})
	default:
		logf("Marti: not supported: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (s *Server) contentURL(r *http.Request, hash string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/Marti/sync/content?hash=" + hash
}

// ---------- enrollment ----------

func (s *Server) signClient(w http.ResponseWriter, r *http.Request, username string, v2 bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	cert, err := s.pki.SignCSR(body, username)
	if err != nil {
		logf("Enrollment for %s failed: %v", username, err)
		http.Error(w, err.Error(), 400)
		return
	}
	clientUID := r.URL.Query().Get("clientUid")
	s.store.Update(func(st *State) {
		st.Certs = append(st.Certs, &IssuedCert{Serial: serialHex(cert), Username: username, ClientUID: clientUID, Issued: time.Now(), Expires: cert.NotAfter})
	})
	logf("Certificate issued for %s (device %s)", username, clientUID)
	signed := base64.StdEncoding.EncodeToString(cert.Raw)
	ca := base64.StdEncoding.EncodeToString(s.pki.CACert.Raw)
	if !v2 {
		// v1 answers with a PKCS#12 keystore of the CA certificate chain
		w.Header().Set("Content-Type", "application/x-pkcs12")
		ts, _ := s.pki.TrustStoreP12(s.store.Config().CertPassword)
		w.Write(ts)
		return
	}
	// like OpenTAKServer: JSON unless the device explicitly asks for XML (iTAK wants JSON as text/plain)
	if accept := r.Header.Get("Accept"); accept == "" || accept == "*/*" || accept == "text/plain" || strings.Contains(accept, "json") {
		ct := "application/json"
		if accept == "text/plain" {
			ct = "text/plain; charset=UTF-8"
		}
		w.Header().Set("Content-Type", ct)
		json.NewEncoder(w).Encode(map[string]string{"signedCert": signed, "ca0": ca, "ca1": ca})
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><enrollment><signedCert>%s</signedCert><ca>%s</ca></enrollment>`, signed, ca)
}

// Device profiles: settings stored for a device (OTS /api/profiles) are delivered as a data package.
func (s *Server) deviceProfile(w http.ResponseWriter, r *http.Request, clientUID string, enrollment bool) {
	var entries []*Profile
	s.store.Read(func(st *State) {
		for _, p := range st.Profiles {
			if !p.Active || (p.EUDUID != "" && p.EUDUID != clientUID) {
				continue
			}
			if (enrollment && p.Enrollment) || (!enrollment && p.Connection) {
				c := *p
				entries = append(entries, &c)
			}
		}
	})
	if len(entries) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var pref strings.Builder
	pref.WriteString(`<?xml version='1.0' encoding='ASCII' standalone='yes'?><preferences><preference version="1" name="com.atakmap.app_preferences">`)
	for _, e := range entries {
		cls := e.ValueClass
		if cls == "" {
			cls = "String"
		}
		fmt.Fprintf(&pref, `<entry key="%s" class="class java.lang.%s">%s</entry>`, xmlEscape(e.Key), xmlEscape(cls), xmlEscape(e.Value))
	}
	pref.WriteString(`</preference></preferences>`)
	zb := buildDataPackage("Profile", map[string][]byte{"profile/profile.pref": []byte(pref.String())}, true)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="profile.zip"`)
	w.Write(zb)
}

// ---------- contacts, groups ----------

func (s *Server) martiClientEndpoints(w http.ResponseWriter, r *http.Request) {
	var data []map[string]any
	s.store.Read(func(st *State) {
		for _, e := range st.EUDs {
			data = append(data, map[string]any{"callsign": e.Callsign, "uid": e.UID, "username": e.Username,
				"lastEventTime": e.LastEventTime.UTC().Format("2006-01-02T15:04:05.000Z"), "lastStatus": e.LastStatus})
		}
	})
	if data == nil {
		data = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"Matcher": "com.bbn.marti.remote.ClientEndpoint", "BaseUrl": "", "ServerConnectString": "",
		"NotificationId": "", "type": "com.bbn.marti.remote.ClientEndpoint", "version": "3", "data": data})
}

func (s *Server) martiGroups(w http.ResponseWriter, id *identity) {
	var data []map[string]any
	s.store.Read(func(st *State) {
		u := findUser(st, id.User)
		var ms []Membership
		if u != nil {
			ms = u.Groups
		} else {
			ms = []Membership{{AnonGroup, "IN"}, {AnonGroup, "OUT"}}
		}
		for i, m := range ms {
			desc := ""
			if g := findGroup(st, m.Group); g != nil {
				desc = g.Description
			}
			data = append(data, map[string]any{"name": m.Group, "direction": m.Direction, "created": "2024-01-01",
				"type": "SYSTEM", "bitpos": i, "active": true, "description": desc})
		}
	})
	if data == nil {
		data = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"version": "3", "type": "com.bbn.marti.remote.groups.Group", "data": data, "nodeId": s.store.Config().ServerUID})
}

// ---------- data packages ----------

func (s *Server) martiUpload(w http.ResponseWriter, r *http.Request, id *identity, mission bool) {
	q := r.URL.Query()
	r.Body = http.MaxBytesReader(w, r.Body, 2<<30)
	meta := Package{Name: q.Get("filename"), CreatorUID: q.Get("creatorUid"), User: id.User}
	if meta.Name == "" {
		meta.Name = q.Get("name")
	}
	if kw := q.Get("keywords"); kw != "" {
		meta.Keywords = strings.Split(kw, ",")
	}
	if !mission {
		meta.Keywords = append(meta.Keywords, "missionpackage")
	}
	var src io.Reader = r.Body
	if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/") {
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var part *multipart.Part
		for {
			part, err = mr.NextPart()
			if err != nil {
				http.Error(w, "no file in upload", 400)
				return
			}
			if part.FileName() != "" || part.FormName() == "assetfile" {
				break
			}
		}
		if meta.Name == "" {
			meta.Name = part.FileName()
		}
		if pct := part.Header.Get("Content-Type"); pct != "" && pct != "application/octet-stream" {
			meta.MIME = pct
		}
		src = part
	}
	pk, err := s.packages.Save(src, meta, q.Get("hash"))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	logf("Data package uploaded: %s (%d bytes) by %s", pk.Name, pk.Size, id.User)
	if mission {
		fmt.Fprint(w, s.contentURL(r, pk.Hash))
		return
	}
	writeJSON(w, 200, pk.Marti())
}

func (s *Server) martiDownload(w http.ResponseWriter, r *http.Request, hash string) {
	pk := s.packages.Get(hash)
	if pk == nil {
		http.NotFound(w, r)
		return
	}
	f, err := s.packages.Open(pk.Hash)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", pk.MIME)
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(pk.Name, `"`, "")+`"`)
	http.ServeContent(w, r, "", pk.Submitted, f)
}

func (s *Server) martiSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kw, tool := strings.ToLower(q.Get("keywords")), q.Get("tool")
	var res []map[string]any
	for _, pk := range s.packages.List() {
		if tool != "" && pk.Tool != tool {
			continue
		}
		if tool == "" && pk.Tool == "private" {
			continue
		}
		if kw != "" && kw != "missionpackage" {
			hit := strings.Contains(strings.ToLower(pk.Name), kw)
			for _, k := range pk.Keywords {
				hit = hit || strings.EqualFold(k, kw)
			}
			if !hit {
				continue
			}
		}
		res = append(res, pk.Marti())
	}
	if res == nil {
		res = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"resultCount": len(res), "results": res})
}

// ---------- video connections (ATAK "Video" list from the server) ----------

// Video list for ATAK / iTAK ("Video" → server feeds), in the format of OpenTAKServer: streams on our
// video server point to this server under the address the device used.
func (s *Server) martiVideo(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		for _, m := range reFeed.FindAllSubmatch(body, -1) {
			inner := m[1]
			alias, link, uid := xmlField(inner, "alias"), xmlField(inner, "url"), xmlField(inner, "uid")
			if link == "" { // OTS / ATAK format: protocol + address + port + path
				proto, addr, port, path := xmlField(inner, "protocol"), xmlField(inner, "address"), xmlField(inner, "port"), xmlField(inner, "path")
				if addr == "" || proto == "" {
					continue
				}
				if i := strings.LastIndex(addr, "@"); i >= 0 {
					addr = addr[i+1:] // never store passwords
				}
				hp := addr
				if port != "" && port != "-1" {
					hp = joinHostPort(addr, atoiDefault(port, 0))
				}
				link = proto + "://" + hp + "/" + strings.TrimPrefix(path, "/")
			}
			if uid == "" {
				uid = randomHex(8)
			}
			s.store.Update(func(st *State) {
				for _, v := range st.Videos {
					if v.UID == uid {
						v.Alias, v.URL = alias, link
						return
					}
				}
				st.Videos = append(st.Videos, &VideoFeed{UID: uid, Alias: orDefault(alias, link), URL: link, Created: time.Now()})
			})
		}
		w.WriteHeader(200)
		return
	}
	host := clientHost(r)
	itak := strings.Contains(r.UserAgent(), "iTAK")
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><videoConnections>`)
	feed := func(uid, alias, proto, addr string, port int, path string) {
		if itak { // iTAK wants the whole address, like OTS sends it
			addr = proto + "://" + joinHostPort(addr, port) + "/" + strings.TrimPrefix(path, "/")
		}
		fmt.Fprintf(&b, `<feed><protocol>%s</protocol><alias>%s</alias><uid>%s</uid><address>%s</address><port>%d</port><roverPort>-1</roverPort><ignoreEmbeddedKLV>false</ignoreEmbeddedKLV><preferredMacAddress></preferredMacAddress><preferredInterfaceAddress></preferredInterfaceAddress><path>/%s</path><buffer></buffer><timeout>10000</timeout><rtspReliable>1</rtspReliable></feed>`,
			xmlEscape(proto), xmlEscape(alias), xmlEscape(uid), xmlEscape(addr), port, xmlEscape(strings.TrimPrefix(path, "/")))
	}
	for _, f := range s.media.Feeds() {
		if f.Path != "" {
			if s.ports.RTSP > 0 {
				feed(f.UID, f.Alias, "rtsp", host, s.ports.RTSP, f.Path)
			}
			continue
		}
		u, err := url.Parse(f.URL)
		if err != nil || u.Host == "" {
			continue
		}
		port := atoiDefault(u.Port(), map[string]int{"rtsp": 554, "rtmp": 1935, "http": 80, "https": 443, "srt": 8890}[u.Scheme])
		path := u.Path
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
		feed(f.UID, f.Alias, u.Scheme, u.Hostname(), port, path)
	}
	b.WriteString(`</videoConnections>`)
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, b.String())
}

func atoiDefault(s string, d int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return d
}

func (s *Server) martiMissions(w http.ResponseWriter) {
	var data []map[string]any
	s.store.Read(func(st *State) {
		for _, m := range st.Missions {
			data = append(data, map[string]any{"name": m.Name, "description": m.Description, "creatorUid": m.CreatorUID,
				"createTime": m.Created.UTC().Format("2006-01-02T15:04:05.000Z"), "tool": m.Tool, "groups": m.Groups,
				"passwordProtected": m.Password != "", "defaultRole": map[string]any{"type": orDefault(m.DefaultRole, "MISSION_SUBSCRIBER")},
				"keywords": []string{}, "uids": []any{}, "contents": []any{}})
		}
	})
	if data == nil {
		data = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"version": "3", "type": "Mission", "data": data, "nodeId": s.store.Config().ServerUID})
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ---------- data package builder (MANIFEST + files) ----------

func buildDataPackage(name string, files map[string][]byte, deleteOnReceive bool) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var contents strings.Builder
	for path := range files {
		fmt.Fprintf(&contents, `<Content ignore="false" zipEntry="%s"/>`, xmlEscape(path))
	}
	manifest := fmt.Sprintf(`<MissionPackageManifest version="2"><Configuration><Parameter name="uid" value="%s"/><Parameter name="name" value="%s"/><Parameter name="onReceiveDelete" value="%v"/></Configuration><Contents>%s</Contents></MissionPackageManifest>`,
		newUUID(), xmlEscape(name), deleteOnReceive, contents.String())
	f, _ := zw.Create("MANIFEST/manifest.xml")
	f.Write([]byte(manifest))
	for path, data := range files {
		f, _ := zw.Create(path)
		f.Write(data)
	}
	zw.Close()
	return buf.Bytes()
}

func newUUID() string {
	h := randomHex(16)
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

// ConnectionPackage: zip for ATAK/WinTAK/iTAK with server address, truststore and client certificate.
// Import it on the device (ATAK: Import → Local SD; WinTAK: drag into the map; iTAK: Settings → Network → Import).
func (s *Server) ConnectionPackage(username, host string) ([]byte, error) {
	cfg := s.store.Config()
	pw := cfg.CertPassword
	trust, err := s.pki.TrustStoreP12(pw)
	if err != nil {
		return nil, err
	}
	client, cert, err := s.pki.NewClientP12(username, pw)
	if err != nil {
		return nil, err
	}
	s.store.Update(func(st *State) {
		st.Certs = append(st.Certs, &IssuedCert{Serial: serialHex(cert), Username: username, ClientUID: "data-package", Issued: time.Now(), Expires: cert.NotAfter})
	})
	desc := cfg.ServerName
	pref := fmt.Sprintf(`<?xml version='1.0' encoding='ASCII' standalone='yes'?>
<preferences>
  <preference version="1" name="cot_streams">
    <entry key="count" class="class java.lang.Integer">1</entry>
    <entry key="description0" class="class java.lang.String">%s</entry>
    <entry key="enabled0" class="class java.lang.Boolean">true</entry>
    <entry key="connectString0" class="class java.lang.String">%s:%d:ssl</entry>
  </preference>
  <preference version="1" name="com.atakmap.app_preferences">
    <entry key="displayServerConnectionWidget" class="class java.lang.Boolean">true</entry>
    <entry key="caLocation" class="class java.lang.String">cert/truststore.p12</entry>
    <entry key="caPassword" class="class java.lang.String">%s</entry>
    <entry key="clientPassword" class="class java.lang.String">%s</entry>
    <entry key="certificateLocation" class="class java.lang.String">cert/%s.p12</entry>
  </preference>
</preferences>
`, xmlEscape(desc), xmlEscape(host), s.ports.SSL, xmlEscape(pw), xmlEscape(pw), xmlEscape(username))
	return buildDataPackage(desc+" – "+username, map[string][]byte{
		"cert/server.pref":          []byte(pref),
		"cert/truststore.p12":       trust,
		"cert/" + username + ".p12": client,
	}, true), nil
}

// QR strings for the device apps
func (s *Server) atakQRString(host, username, token string) string {
	return "tak://com.atakmap.app/enroll?host=" + host + "&username=" + urlQuery(username) + "&token=" + urlQuery(token)
}

func (s *Server) itakQRString(host string) string {
	name := strings.NewReplacer(",", " ").Replace(s.store.Config().ServerName)
	return name + "," + host + "," + strconv.Itoa(s.ports.SSL) + ",SSL"
}

func urlQuery(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

var reFeed = regexp.MustCompile(`(?s)<feed>(.*?)</feed>`)

func xmlField(b []byte, name string) string {
	re := regexp.MustCompile(`(?s)<` + name + `>(.*?)</` + name + `>`)
	if m := re.FindSubmatch(b); m != nil {
		return strings.TrimSpace(html.UnescapeString(string(m[1])))
	}
	return ""
}
