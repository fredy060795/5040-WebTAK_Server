package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The video tests need a MediaMTX program (WTS_MEDIAMTX=/path/to/mediamtx) and ffmpeg/ffprobe.
func needVideo(t *testing.T) {
	t.Helper()
	if os.Getenv("WTS_MEDIAMTX") == "" {
		t.Skip("set WTS_MEDIAMTX to a MediaMTX program to run the video tests")
	}
	for _, p := range []string{"ffmpeg", "ffprobe"} {
		if _, err := exec.LookPath(p); err != nil {
			t.Skip(p + " not installed")
		}
	}
}

func startVideoServer(t *testing.T, name string) *Server {
	t.Helper()
	srv := startServer(t, name)
	srv.store.Update(func(s *State) { s.Config.VideoEnabled = true })
	srv.media.Kick()
	waitUntil(t, "video server running", 20*time.Second, func() bool { _, _, ok := srv.media.Status(); return ok })
	return srv
}

func waitUntil(t *testing.T, what string, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

// publish sends a test picture to the video server until the test ends.
func publish(t *testing.T, url string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "ffmpeg", "-hide_banner", "-loglevel", "error", "-re", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=10",
		"-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-g", "10", "-f", "rtsp", "-rtsp_transport", "tcp", url)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); cmd.Wait() })
	return cmd
}

// probe reads a stream and returns the video codec ("" if it cannot be played).
func probe(url string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ffprobe", "-v", "error", "-rtsp_transport", "tcp", "-select_streams", "v:0",
		"-show_entries", "stream=codec_name", "-of", "csv=p=0", url).Output()
	return strings.TrimSpace(string(out))
}

func hasFeed(s *Server, path string, live bool) bool {
	for _, f := range s.media.Feeds() {
		if f.Path == path && (!live || f.Live) {
			return true
		}
	}
	return false
}

func TestVideoPublishWatchAndVCM(t *testing.T) {
	needVideo(t)
	srv := startVideoServer(t, "Alpha")
	srv.CreateUser("pilot", "pilot-pass", false, nil)
	rtsp := srv.ports.RTSP

	// wrong password: refused
	bad := exec.Command("ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc=size=160x120:rate=5", "-t", "2",
		"-c:v", "libx264", "-preset", "ultrafast", "-f", "rtsp", "-rtsp_transport", "tcp", fmt.Sprintf("rtsp://pilot:wrong@127.0.0.1:%d/bad", rtsp))
	if err := bad.Run(); err == nil {
		t.Fatal("publishing with a wrong password worked")
	}

	publish(t, fmt.Sprintf("rtsp://pilot:pilot-pass@127.0.0.1:%d/drone-1", rtsp))
	waitUntil(t, "stream live", 20*time.Second, func() bool { srv.media.poll(); return hasFeed(srv, "drone-1", true) })
	if c := probe(fmt.Sprintf("rtsp://127.0.0.1:%d/drone-1", rtsp)); c != "h264" {
		t.Fatalf("watching: codec %q", c)
	}
	// ATAK video list
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/Marti/vcm", srv.ports.HTTP))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<path>/drone-1</path>") || !strings.Contains(string(body), fmt.Sprintf("<port>%d</port>", rtsp)) {
		t.Fatalf("vcm: %s", body)
	}
	// watching with login required
	srv.store.Update(func(s *State) { s.Config.VideoReadAuth = true })
	if c := probe(fmt.Sprintf("rtsp://127.0.0.1:%d/drone-1", rtsp)); c != "" {
		t.Fatal("watching without login worked")
	}
	if c := probe(fmt.Sprintf("rtsp://pilot:pilot-pass@127.0.0.1:%d/drone-1", rtsp)); c != "h264" {
		t.Fatalf("watching with login: %q", c)
	}

	// pulled stream (on demand) from another address, OTS API style
	if err := srv.SaveStream("relay", fmt.Sprintf("rtsp://pilot:pilot-pass@127.0.0.1:%d/drone-1", rtsp), "Relay", "pilot", false); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "pulled stream configured", 10*time.Second, func() bool { return hasFeed(srv, "relay", false) })
	if c := probe(fmt.Sprintf("rtsp://pilot:pilot-pass@127.0.0.1:%d/relay", rtsp)); c != "h264" {
		t.Fatalf("pulled stream: %q", c)
	}
}

func TestFederationVideoBothDirections(t *testing.T) {
	needVideo(t)
	a := startVideoServer(t, "Alpha")
	b := startVideoServer(t, "Bravo")
	a.CreateUser("ua", "secret-pass", false, nil)
	b.CreateUser("ub", "secret-pass", false, nil)
	link(t, a, b) // B dials A; video must still flow both ways through the one connection
	publish(t, fmt.Sprintf("rtsp://ua:secret-pass@127.0.0.1:%d/cam-a", a.ports.RTSP))
	publish(t, fmt.Sprintf("rtsp://ub:secret-pass@127.0.0.1:%d/cam-b", b.ports.RTSP))
	waitUntil(t, "A's camera listed on B", 30*time.Second, func() bool { return hasFeed(b, "fed-alpha/cam-a", false) })
	waitUntil(t, "B's camera listed on A", 30*time.Second, func() bool { return hasFeed(a, "fed-bravo/cam-b", false) })
	time.Sleep(time.Second) // MediaMTX applies the new paths
	if c := probe(fmt.Sprintf("rtsp://127.0.0.1:%d/fed-alpha/cam-a", b.ports.RTSP)); c != "h264" {
		t.Fatalf("A's video on B: %q", c)
	}
	if c := probe(fmt.Sprintf("rtsp://127.0.0.1:%d/fed-bravo/cam-b", a.ports.RTSP)); c != "h264" {
		t.Fatalf("B's video on A: %q", c)
	}
}
