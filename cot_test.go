package main

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestEventReaderSplitsStream(t *testing.T) {
	stream := `<?xml version="1.0"?><event version="2.0" uid="a" type="a-f-G"><detail remarks="x > y"/></event>  junk
<event uid="b" type="t-x-c-t"/><events>no</events><event uid="c" type="b-t-f"><detail><remarks>&lt;event&gt;</remarks></detail></event>`
	er := NewEventReader(iotest.OneByteReader(strings.NewReader(stream)))
	var uids []string
	for {
		raw, err := er.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		ev, err := ParseEvent(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		uids = append(uids, ev.UID)
	}
	if strings.Join(uids, ",") != "a,b,c" {
		t.Fatalf("got %v", uids)
	}
}

func TestAddFlowTag(t *testing.T) {
	cases := []string{
		`<event uid="1"><detail><contact callsign="A"/></detail></event>`,
		`<event uid="1"><detail/></event>`,
		`<event uid="1"></event>`,
		`<event uid="1"><detail><_flow-tags_ other="x"/></detail></event>`,
		`<event uid="1"><detail><_flow-tags_ other="x"></_flow-tags_></detail></event>`,
	}
	for _, c := range cases {
		out := AddFlowTag([]byte(c), "WebTAK-Server-abc")
		ev, err := ParseEvent(out)
		if err != nil {
			t.Fatalf("%s -> %s: %v", c, out, err)
		}
		if !ev.HasFlowTag("WebTAK-Server-abc") {
			t.Fatalf("flow tag missing: %s", out)
		}
		if strings.Contains(c, "other") && !ev.HasFlowTag("other") {
			t.Fatalf("existing tag lost: %s", out)
		}
	}
}

func TestRewriteSenderURL(t *testing.T) {
	in := `<event uid="1" type="b-f-t-r"><detail><fileshare filename="a.zip" senderUrl="https://old:8443/Marti/sync/content?hash=1&amp;x=2" sha256="1"/></detail></event>`
	out := string(RewriteSenderURL([]byte(in), "https://new:8443/Marti/sync/content?hash=1"))
	ev, err := ParseEvent([]byte(out))
	if err != nil || ev.Detail.Fileshare.SenderURL != "https://new:8443/Marti/sync/content?hash=1" {
		t.Fatalf("got %s (%v)", out, err)
	}
}

func TestInviteRoundTrip(t *testing.T) {
	if _, err := ParseInvite("hello"); err == nil {
		t.Fatal("expected error")
	}
}
