package main

import (
	"fmt"
	"testing"
	"time"
)

// The bridge talks to the other server like ATAK does. WebTAK Server offers the same interfaces as
// OpenTAKServer (enrollment, SSL streaming, /Marti/vcm, /api/login, /api/mediamtx/stream/*), so a second
// WebTAK Server stands in for OTS here.
func TestBridgeToTAKServer(t *testing.T) {
	ots := startServer(t, "Alpha")
	wts := startServer(t, "Bravo")
	ots.CreateUser("bridge", "bridge-pass", false, nil)
	if _, err := wts.bridges.Add(BridgeInput{Name: "Alpha", Host: "127.0.0.1", Username: "bridge", Password: "wrong", TLS: true,
		StreamPort: ots.ports.SSL, EnrollPort: ots.ports.Enroll}); err == nil {
		t.Fatal("bridge with a wrong password was accepted")
	}
	if _, err := wts.bridges.Add(BridgeInput{Name: "Alpha", Host: "127.0.0.1", Username: "bridge", Password: "bridge-pass", TLS: true,
		StreamPort: ots.ports.SSL, EnrollPort: ots.ports.Enroll, APIPort: ots.ports.HTTPS, WebPort: ots.ports.HTTPS}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "bridge connected", 10*time.Second, func() bool {
		st := wts.bridges.Status()
		return len(st) == 1 && st[0]["connected"] == true
	})
	co := dialTCP(t, ots.ports.TCP)
	cw := dialTCP(t, wts.ports.TCP)
	co.send(sa("uid-ots", "OTS-USER"))
	co.waitFor("bridge announces itself on the other server", func(e *Event) bool { return e.Callsign() == "Bravo (WebTAK)" })
	cw.waitFor("OTS device at WebTAK", uidIs("uid-ots"))
	cw.send(sa("uid-wts", "WTS-USER"))
	co.waitFor("WebTAK device at OTS", uidIs("uid-wts"))
	time.Sleep(500 * time.Millisecond)
	if n := cw.count(uidIs("uid-wts")); n != 0 {
		t.Fatalf("own event came back %d times", n)
	}
	if n := co.count(uidIs("uid-ots")); n != 0 {
		t.Fatalf("OTS event echoed back %d times", n)
	}
}

func TestBridgeVideo(t *testing.T) {
	needVideo(t)
	old := bridgeVideoInterval
	bridgeVideoInterval = time.Second
	defer func() { bridgeVideoInterval = old }()
	ots := startVideoServer(t, "Alpha")
	wts := startVideoServer(t, "Bravo")
	ots.CreateUser("bridge", "bridge-pass", false, nil)
	wts.CreateUser("cam", "cam-pass-1", false, nil)
	if _, err := wts.bridges.Add(BridgeInput{Name: "Alpha", Host: "127.0.0.1", Username: "bridge", Password: "bridge-pass", TLS: true,
		StreamPort: ots.ports.SSL, EnrollPort: ots.ports.Enroll, APIPort: ots.ports.HTTPS, WebPort: ots.ports.HTTPS, RTSPPort: ots.ports.RTSP,
		ImportVideo: true, ExportVideo: true}); err != nil {
		t.Fatal(err)
	}
	publish(t, fmt.Sprintf("rtsp://bridge:bridge-pass@127.0.0.1:%d/cam-ots", ots.ports.RTSP))
	publish(t, fmt.Sprintf("rtsp://cam:cam-pass-1@127.0.0.1:%d/cam-wts", wts.ports.RTSP))
	// OTS video shown on WebTAK Server (pulled with the bridge user)
	waitUntil(t, "OTS video listed", 30*time.Second, func() bool { return hasFeed(wts, "ots-alpha/cam-ots", false) })
	time.Sleep(time.Second)
	if c := probe(fmt.Sprintf("rtsp://127.0.0.1:%d/ots-alpha/cam-ots", wts.ports.RTSP)); c != "h264" {
		t.Fatalf("OTS video on WebTAK: %q", c)
	}
	// WebTAK video registered on OTS through /api/mediamtx/stream/add, OTS pulls it from us
	waitUntil(t, "WebTAK video registered on OTS", 30*time.Second, func() bool { return hasFeed(ots, "wts-bravo/cam-wts", false) })
	time.Sleep(time.Second)
	if c := probe(fmt.Sprintf("rtsp://127.0.0.1:%d/wts-bravo/cam-wts", ots.ports.RTSP)); c != "h264" {
		t.Fatalf("WebTAK video on OTS: %q", c)
	}
	// our own stream registered on OTS must not come back as an OTS stream
	time.Sleep(2 * time.Second)
	for _, f := range wts.media.Feeds() {
		if f.Path == "ots-alpha/wts-bravo/cam-wts" {
			t.Fatal("own stream imported back")
		}
	}
}
