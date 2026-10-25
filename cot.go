package main

// Cursor on Target (CoT) XML: splitting the TCP stream into events, reading the fields the
// server needs, and small edits (flow tags for federation, file share links).

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxEventSize = 8 << 20 // 8 MB, larger events are dropped

type Event struct {
	XMLName xml.Name `xml:"event"`
	UID     string   `xml:"uid,attr"`
	Type    string   `xml:"type,attr"`
	How     string   `xml:"how,attr"`
	Time    string   `xml:"time,attr"`
	Start   string   `xml:"start,attr"`
	Stale   string   `xml:"stale,attr"`
	Point   struct {
		Lat float64 `xml:"lat,attr"`
		Lon float64 `xml:"lon,attr"`
		Hae string  `xml:"hae,attr"`
	} `xml:"point"`
	Detail struct {
		Contact *struct {
			Callsign string `xml:"callsign,attr"`
			Endpoint string `xml:"endpoint,attr"`
			Phone    string `xml:"phone,attr"`
		} `xml:"contact"`
		Group *struct {
			Name string `xml:"name,attr"`
			Role string `xml:"role,attr"`
		} `xml:"__group"`
		Takv *struct {
			Device   string `xml:"device,attr"`
			Platform string `xml:"platform,attr"`
			OS       string `xml:"os,attr"`
			Version  string `xml:"version,attr"`
		} `xml:"takv"`
		Marti *struct {
			Dest []struct {
				Callsign string `xml:"callsign,attr"`
				UID      string `xml:"uid,attr"`
				Mission  string `xml:"mission,attr"`
			} `xml:"dest"`
		} `xml:"marti"`
		FlowTags *struct {
			Attrs []xml.Attr `xml:",any,attr"`
		} `xml:"_flow-tags_"`
		Fileshare *struct {
			Filename  string `xml:"filename,attr"`
			SenderURL string `xml:"senderUrl,attr"`
			Size      int64  `xml:"sizeInBytes,attr"`
			SHA256    string `xml:"sha256,attr"`
			Name      string `xml:"name,attr"`
		} `xml:"fileshare"`
		Link []struct {
			UID      string `xml:"uid,attr"`
			Relation string `xml:"relation,attr"`
		} `xml:"link"`
	} `xml:"detail"`
}

func ParseEvent(raw []byte) (*Event, error) {
	var ev Event
	if err := xml.Unmarshal(raw, &ev); err != nil {
		return nil, err
	}
	if ev.UID == "" && ev.Type == "" {
		return nil, errors.New("not a CoT event")
	}
	return &ev, nil
}

func (e *Event) Callsign() string {
	if e.Detail.Contact != nil {
		return e.Detail.Contact.Callsign
	}
	return ""
}

// IsSA: position report of a device (self) – has contact with endpoint or takv.
func (e *Event) IsSA() bool {
	return strings.HasPrefix(e.Type, "a-") && e.Detail.Contact != nil && (e.Detail.Takv != nil || e.Detail.Contact.Endpoint != "")
}

func (e *Event) Destinations() (callsigns, uids []string) {
	if e.Detail.Marti == nil {
		return
	}
	for _, d := range e.Detail.Marti.Dest {
		if d.Callsign != "" {
			callsigns = append(callsigns, d.Callsign)
		}
		if d.UID != "" {
			uids = append(uids, d.UID)
		}
	}
	return
}

func (e *Event) HasFlowTag(key string) bool {
	if e.Detail.FlowTags == nil {
		return false
	}
	for _, a := range e.Detail.FlowTags.Attrs {
		if a.Name.Local == key {
			return true
		}
	}
	return false
}

func (e *Event) StaleTime() time.Time {
	t, err := time.Parse(time.RFC3339Nano, e.Stale)
	if err != nil {
		return time.Now().Add(5 * time.Minute)
	}
	return t
}

// ---------- stream splitting ----------

// EventReader cuts a CoT XML stream into single <event> documents. It tolerates XML declarations,
// whitespace and junk between events and handles '>' inside quoted attribute values.
type EventReader struct {
	r   *bufio.Reader
	buf []byte
}

func NewEventReader(r io.Reader) *EventReader {
	return &EventReader{r: bufio.NewReaderSize(r, 64<<10)}
}

var (
	evStart = []byte("<event")
	evEnd   = []byte("</event>")
)

func (er *EventReader) fill() error {
	tmp := make([]byte, 32<<10)
	n, err := er.r.Read(tmp)
	er.buf = append(er.buf, tmp[:n]...)
	if n > 0 {
		return nil
	}
	if err == nil {
		err = io.ErrNoProgress
	}
	return err
}

func (er *EventReader) Next() ([]byte, error) {
	for {
		i := bytes.Index(er.buf, evStart)
		if i < 0 {
			// keep a possible partial "<even" at the end
			if len(er.buf) > len(evStart) {
				er.buf = append(er.buf[:0], er.buf[len(er.buf)-len(evStart):]...)
			}
			if err := er.fill(); err != nil {
				return nil, err
			}
			continue
		}
		if i > 0 {
			er.buf = er.buf[i:]
		}
		// next char must end the tag name ("<events" is not an event)
		if len(er.buf) <= len(evStart) {
			if err := er.fill(); err != nil {
				return nil, err
			}
			continue
		}
		if c := er.buf[len(evStart)]; c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '>' && c != '/' {
			er.buf = er.buf[1:]
			continue
		}
		// find end of the start tag, respecting quotes
		end, selfClosing := -1, false
		var q byte
		for j := len(evStart); j < len(er.buf); j++ {
			c := er.buf[j]
			if q != 0 {
				if c == q {
					q = 0
				}
				continue
			}
			if c == '"' || c == '\'' {
				q = c
			} else if c == '>' {
				end, selfClosing = j+1, er.buf[j-1] == '/'
				break
			}
		}
		if end < 0 {
			if len(er.buf) > maxEventSize {
				er.buf = er.buf[:0]
				continue
			}
			if err := er.fill(); err != nil {
				return nil, err
			}
			continue
		}
		if selfClosing {
			ev := append([]byte(nil), er.buf[:end]...)
			er.buf = er.buf[end:]
			return ev, nil
		}
		k := bytes.Index(er.buf[end:], evEnd)
		if k < 0 {
			if len(er.buf) > maxEventSize {
				er.buf = er.buf[:0]
				continue
			}
			if err := er.fill(); err != nil {
				return nil, err
			}
			continue
		}
		stop := end + k + len(evEnd)
		ev := append([]byte(nil), er.buf[:stop]...)
		er.buf = er.buf[stop:]
		return ev, nil
	}
}

// ---------- edits on raw events ----------

var reFlowTags = regexp.MustCompile(`<_flow-tags_(\s[^>]*?)?\s*(/?)>`)

// AddFlowTag marks an event as having passed this server (loop protection for federation,
// the same mechanism TAK Server uses).
func AddFlowTag(raw []byte, key string) []byte {
	attr := fmt.Sprintf(` %s="%s"`, key, time.Now().UTC().Format(time.RFC3339))
	if loc := reFlowTags.FindSubmatchIndex(raw); loc != nil {
		// insert the attribute before "/>" or ">"
		pos := loc[1] - 1
		if loc[5] > loc[4] { // self-closing
			pos = loc[4]
		}
		for pos > 0 && (raw[pos-1] == ' ' || raw[pos-1] == '\t') {
			pos--
		}
		return concat(raw[:pos], []byte(attr), raw[pos:])
	}
	tag := []byte("<_flow-tags_" + attr + "/>")
	if i := bytes.Index(raw, []byte("</detail>")); i >= 0 {
		return concat(raw[:i], tag, raw[i:])
	}
	if loc := regexp.MustCompile(`<detail\s*/>`).FindIndex(raw); loc != nil {
		return concat(raw[:loc[0]], []byte("<detail>"), tag, []byte("</detail>"), raw[loc[1]:])
	}
	if i := bytes.LastIndex(raw, evEnd); i >= 0 {
		return concat(raw[:i], []byte("<detail>"), tag, []byte("</detail>"), raw[i:])
	}
	return raw
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var reSenderURL = regexp.MustCompile(`senderUrl="[^"]*"`)

// RewriteSenderURL points the download link of a shared data package to this server, as the
// receiving device sees it.
func RewriteSenderURL(raw []byte, url string) []byte {
	return reSenderURL.ReplaceAll(raw, []byte(`senderUrl="`+xmlEscape(url)+`"`))
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return strings.ReplaceAll(b.String(), `"`, "&quot;")
}

func cotTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func PongEvent() []byte {
	now := time.Now()
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><event version="2.0" uid="takPong" type="t-x-c-t-r" how="h-g-i-g-o" time="%s" start="%s" stale="%s"><point lat="0.0" lon="0.0" hae="0.0" ce="9999999.0" le="9999999.0"/><detail/></event>`,
		cotTime(now), cotTime(now), cotTime(now.Add(20*time.Second))))
}

// ServerChat: a GeoChat message from the server (e.g. broadcast from the web UI).
func ServerChat(serverUID, serverName, text string) []byte {
	now := time.Now()
	msgID := randomHex(8)
	uid := "WebTAK-Server-" + serverUID
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><event version="2.0" uid="GeoChat.%s.All Chat Rooms.%s" type="b-t-f" how="h-g-i-g-o" time="%s" start="%s" stale="%s"><point lat="0.0" lon="0.0" hae="9999999.0" ce="9999999.0" le="9999999.0"/><detail><__chat parent="RootContactGroup" groupOwner="false" messageId="%s" chatroom="All Chat Rooms" id="All Chat Rooms" senderCallsign="%s"><chatgrp uid0="%s" uid1="All Chat Rooms" id="All Chat Rooms"/></__chat><link uid="%s" type="a-f-G-U-C" relation="p-p"/><remarks source="BAO.F.ATAK.%s" to="All Chat Rooms" time="%s">%s</remarks></detail></event>`,
		uid, msgID, cotTime(now), cotTime(now), cotTime(now.Add(24*time.Hour)), msgID, xmlEscape(serverName), uid, uid, uid, cotTime(now), xmlEscape(text)))
}

func atof(s string) float64 { f, _ := strconv.ParseFloat(s, 64); return f }
