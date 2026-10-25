package main

// Video server: MediaMTX (https://github.com/bluenviron/mediamtx), the same media server
// OpenTAKServer uses. WebTAK Server starts and configures it by itself:
//
//   - ports like OTS: RTSP 8554, RTMP 1935, HLS 8888, WebRTC 8889, SRT 8890
//   - logins are checked against the TAK users (publishing always, watching optionally)
//   - cameras/drones push to any path name; sources can also be pulled on demand
//   - streams of federated servers and of linked OTS servers appear here as well
//
// The MediaMTX program is taken from next to webtak-server, from the data folder, or downloaded
// automatically on first use.

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const mediamtxVersion = "v1.21.2"

type liveStream struct {
	Name       string `json:"name"`
	Ready      bool   `json:"ready"`
	Source     string `json:"source"` // rtspSession, rtmpConn, srtConn, webRTCSession, rtspSource …
	Readers    int    `json:"readers"`
	Tracks     []string
	BytesIn    uint64 `json:"bytesIn"`
	ReadySince time.Time
}

// autoPath: a stream managed automatically (from a federated server or a linked TAK server).
type autoPath struct {
	Name       string
	Source     string
	Alias      string
	Origin     string // server UID the video comes from
	OriginName string
	OPath      string // path on the origin server
	Hops       int
	Owner      string // federation link id or bridge id
	TCP        bool   // pull with RTSP over TCP (needed through the federation tunnel)
}

type Media struct {
	srv *Server

	mu       sync.Mutex
	status   string
	bin      string
	apiBase  string
	key      string
	authPort int
	live     map[string]liveStream
	auto     map[string]map[string]autoPath // owner -> name -> path
	running  bool

	kick     chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	authLn   net.Listener
	client   *http.Client
}

func NewMedia(srv *Server) *Media {
	return &Media{srv: srv, status: "starting", live: map[string]liveStream{}, auto: map[string]map[string]autoPath{},
		kick: make(chan struct{}, 1), stop: make(chan struct{}), key: randomHex(16), client: &http.Client{Timeout: 5 * time.Second}}
}

func (m *Media) setStatus(s string) {
	m.mu.Lock()
	if m.status != s && strings.HasPrefix(s, "error") {
		logf("Video server: %s", strings.TrimPrefix(s, "error: "))
	}
	m.status = s
	m.mu.Unlock()
}

func (m *Media) Status() (status, bin string, running bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status, m.bin, m.running
}

// Kick re-applies the stream list (after feeds changed).
func (m *Media) Kick() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func (m *Media) Start() error {
	// login checks of MediaMTX arrive here (only from this computer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	m.authLn = ln
	m.authPort = ln.Addr().(*net.TCPAddr).Port
	m.resolvePorts()
	hs := &http.Server{Handler: http.HandlerFunc(m.handleAuth), ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(ln)
	m.wg.Add(1)
	go m.run()
	return nil
}

func (m *Media) Stop() {
	m.stopOnce.Do(func() { close(m.stop) })
	if m.authLn != nil {
		m.authLn.Close()
	}
	m.wg.Wait()
}

// ---------- program ----------

func mediamtxExe() string {
	if runtime.GOOS == "windows" {
		return "mediamtx.exe"
	}
	return "mediamtx"
}

func (m *Media) findBinary() string {
	cfg := m.srv.store.Config()
	cands := []string{cfg.MediaMTXPath, os.Getenv("WTS_MEDIAMTX")}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		cands = append(cands, filepath.Join(dir, mediamtxExe()), filepath.Join(dir, "mediamtx", mediamtxExe()))
	}
	cands = append(cands, filepath.Join(m.srv.dataDir, "mediamtx", mediamtxExe()))
	for _, c := range cands {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	if p, err := exec.LookPath("mediamtx"); err == nil {
		return p
	}
	return ""
}

// mediamtxAsset: name of the MediaMTX download for this system.
func mediamtxAsset() (string, error) {
	osName, arch, ext := runtime.GOOS, runtime.GOARCH, ".tar.gz"
	switch runtime.GOOS {
	case "windows":
		ext, arch = ".zip", "amd64" // Windows on ARM runs the amd64 build
	case "linux":
		switch runtime.GOARCH {
		case "amd64", "arm64":
		case "arm":
			arch = "armv7"
			if goarm() == "6" {
				arch = "armv6"
			}
		default:
			return "", fmt.Errorf("MediaMTX is not available for linux/%s", runtime.GOARCH)
		}
	case "darwin":
	default:
		return "", fmt.Errorf("MediaMTX is not available for %s", runtime.GOOS)
	}
	return fmt.Sprintf("mediamtx_%s_%s_%s%s", mediamtxVersion, osName, arch, ext), nil
}

func goarm() string {
	if v := os.Getenv("GOARM"); v != "" {
		return v
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil && strings.Contains(string(b), "ARMv6") {
		return "6"
	}
	return "7"
}

// download fetches MediaMTX from GitHub into the data folder.
func (m *Media) download() (string, error) {
	asset, err := mediamtxAsset()
	if err != nil {
		return "", err
	}
	u := "https://github.com/bluenviron/mediamtx/releases/download/" + mediamtxVersion + "/" + asset
	logf("Video server: downloading MediaMTX %s …", mediamtxVersion)
	c := &http.Client{Timeout: 5 * time.Minute}
	resp, err := c.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download %s: HTTP %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
	if err != nil {
		return "", err
	}
	dir := filepath.Join(m.srv.dataDir, "mediamtx")
	os.MkdirAll(dir, 0o755)
	target := filepath.Join(dir, mediamtxExe())
	var bin []byte
	if strings.HasSuffix(asset, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return "", err
		}
		for _, f := range zr.File {
			if filepath.Base(f.Name) == mediamtxExe() {
				rc, _ := f.Open()
				bin, _ = io.ReadAll(rc)
				rc.Close()
			}
		}
	} else {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return "", err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			if filepath.Base(h.Name) == mediamtxExe() {
				bin, _ = io.ReadAll(tr)
			}
		}
	}
	if len(bin) == 0 {
		return "", errors.New("MediaMTX program not found in the download")
	}
	if err := os.WriteFile(target+".new", bin, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(target+".new", target); err != nil {
		return "", err
	}
	logf("Video server: MediaMTX installed in %s", dir)
	return target, nil
}

// ---------- configuration ----------

func freePort(network string) int {
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return 0
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// resolvePorts gives ports set to 0 (tests) a free port; -1 switches the protocol off.
func (m *Media) resolvePorts() {
	p := &m.srv.ports
	for _, x := range []*int{&p.RTSP, &p.RTMP, &p.HLS, &p.WebRTC, &p.MediaAPI} {
		if *x == 0 {
			*x = freePort("tcp")
		}
	}
	if p.WebRTCUDP == 0 {
		p.WebRTCUDP = freePort("udp")
	}
	if p.SRT == 0 {
		p.SRT = freePort("udp")
	}
}

func yamlStr(s string) string {
	b, _ := json.Marshal(s) // JSON strings are valid YAML
	return string(b)
}

func (m *Media) writeConfig(path string) error {
	cfg := m.srv.store.Config()
	p := m.srv.ports
	bind := m.srv.bindAddr
	addr := func(port int) string { return yamlStr(joinHostPort(bind, port)) }
	onOff := func(port int) string {
		if port > 0 {
			return "yes"
		}
		return "no"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by WebTAK Server – changes are overwritten. Use the web interface instead.\n")
	fmt.Fprintf(&b, "logLevel: info\nlogDestinations: [stdout]\nreadTimeout: 10s\nwriteTimeout: 10s\nwriteQueueSize: 1024\n")
	fmt.Fprintf(&b, "authMethod: http\nauthHTTPAddress: %s\n", yamlStr(fmt.Sprintf("http://127.0.0.1:%d/auth?key=%s", m.authPort, m.key)))
	fmt.Fprintf(&b, "api: yes\napiAddress: %s\n", yamlStr(fmt.Sprintf("127.0.0.1:%d", p.MediaAPI)))
	fmt.Fprintf(&b, "metrics: no\npprof: no\nplayback: no\n")
	fmt.Fprintf(&b, "rtsp: %s\nrtspAddress: %s\nrtspEncryption: \"no\"\n", onOff(p.RTSP), addr(p.RTSP))
	if p.RTP > 0 {
		fmt.Fprintf(&b, "rtspTransports: [udp, multicast, tcp]\nrtpAddress: %s\nrtcpAddress: %s\n", addr(p.RTP), addr(p.RTP+1))
	} else {
		fmt.Fprintf(&b, "rtspTransports: [tcp]\n")
	}
	fmt.Fprintf(&b, "rtmp: %s\nrtmpAddress: %s\nrtmpEncryption: \"no\"\n", onOff(p.RTMP), addr(p.RTMP))
	fmt.Fprintf(&b, "hls: %s\nhlsAddress: %s\nhlsAllowOrigins: ['*']\n", onOff(p.HLS), addr(p.HLS))
	fmt.Fprintf(&b, "webrtc: %s\nwebrtcAddress: %s\nwebrtcAllowOrigins: ['*']\nwebrtcLocalUDPAddress: %s\n", onOff(p.WebRTC), addr(p.WebRTC), addr(p.WebRTCUDP))
	var hosts []string
	if h := strings.TrimSpace(cfg.PublicHost); h != "" && net.ParseIP(h) != nil {
		hosts = append(hosts, yamlStr(h))
	}
	for _, ip := range localIPs() {
		hosts = append(hosts, yamlStr(ip))
	}
	fmt.Fprintf(&b, "webrtcAdditionalHosts: [%s]\n", strings.Join(hosts, ", "))
	fmt.Fprintf(&b, "srt: %s\nsrtAddress: %s\n", onOff(p.SRT), addr(p.SRT))
	fmt.Fprintf(&b, "moq: no\n")
	fmt.Fprintf(&b, "paths:\n")
	for _, d := range m.desired() {
		fmt.Fprintf(&b, "  %s:\n    source: %s\n    sourceOnDemand: yes\n", yamlStr(d.Name), yamlStr(d.Source))
		if d.TCP {
			fmt.Fprintf(&b, "    rtspTransport: tcp\n")
		}
	}
	fmt.Fprintf(&b, "  all_others:\n")
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// desired: all streams that are pulled from somewhere (own feeds + automatic ones).
func (m *Media) desired() []autoPath {
	var out []autoPath
	m.srv.store.Read(func(s *State) {
		for _, f := range s.Videos {
			if f.Path != "" && f.Source != "" {
				out = append(out, autoPath{Name: f.Path, Source: f.Source, Alias: f.Alias})
			}
		}
	})
	m.mu.Lock()
	for _, paths := range m.auto {
		for _, a := range paths {
			out = append(out, a)
		}
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---------- process ----------

func (m *Media) run() {
	defer m.wg.Done()
	backoff := 2 * time.Second
	for {
		select {
		case <-m.stop:
			return
		default:
		}
		cfg := m.srv.store.Config()
		if !cfg.VideoEnabled {
			m.setStatus("switched off")
			if !m.wait(10 * time.Second) {
				return
			}
			continue
		}
		bin := m.findBinary()
		if bin == "" {
			m.setStatus("downloading MediaMTX …")
			var err error
			if bin, err = m.download(); err != nil {
				m.setStatus("error: MediaMTX is missing and could not be downloaded (" + err.Error() + "). Put mediamtx" +
					map[bool]string{true: ".exe", false: ""}[runtime.GOOS == "windows"] + " next to webtak-server or into " + filepath.Join(m.srv.dataDir, "mediamtx"))
				if !m.wait(5 * time.Minute) {
					return
				}
				continue
			}
		}
		m.mu.Lock()
		m.bin = bin
		m.mu.Unlock()
		started := time.Now()
		err := m.runOnce(bin)
		if m.isStopped() {
			return
		}
		if time.Since(started) > time.Minute {
			backoff = 2 * time.Second
		}
		m.setStatus("error: MediaMTX stopped: " + fmt.Sprint(err) + " – restarting")
		if !m.wait(backoff) {
			return
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func (m *Media) isStopped() bool {
	select {
	case <-m.stop:
		return true
	default:
		return false
	}
}

func (m *Media) wait(d time.Duration) bool {
	select {
	case <-m.stop:
		return false
	case <-m.kick: // settings changed
		return true
	case <-time.After(d):
		return true
	}
}

var reMtxLog = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d (\w{3}) (.*)$`)

func (m *Media) runOnce(bin string) error {
	dir := filepath.Join(m.srv.dataDir, "mediamtx")
	os.MkdirAll(dir, 0o755)
	conf := filepath.Join(dir, "mediamtx.yml")
	if err := m.writeConfig(conf); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, conf)
	cmd.Dir = dir
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	m.mu.Lock()
	m.apiBase = fmt.Sprintf("http://127.0.0.1:%d", m.srv.ports.MediaAPI)
	m.mu.Unlock()
	m.setStatus("starting")
	var lastErr string
	var logMu sync.Mutex
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			line := sc.Text()
			level, msg := "", line
			if mm := reMtxLog.FindStringSubmatch(line); mm != nil {
				level, msg = mm[1], mm[2]
			} else if strings.HasPrefix(line, ",") || strings.TrimSpace(line) == "" {
				continue // continuation of the version line
			}
			if level == "ERR" || level == "WAR" || level == "" {
				logMu.Lock()
				lastErr = msg
				logMu.Unlock()
			}
			if level == "ERR" || level == "WAR" || level == "" || strings.Contains(msg, "is publishing") || strings.Contains(msg, "is reading") ||
				strings.Contains(msg, "listener opened") || strings.Contains(msg, "MediaMTX v") {
				logf("Video: %s", msg)
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	first := true
	for {
		select {
		case <-m.stop:
			cancel()
			<-done
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			return nil
		case err := <-done:
			m.mu.Lock()
			m.running, m.live = false, map[string]liveStream{}
			m.mu.Unlock()
			logMu.Lock()
			defer logMu.Unlock()
			if lastErr != "" {
				return fmt.Errorf("%v (%s)", err, lastErr)
			}
			return err
		case <-m.kick:
			if !m.srv.store.Config().VideoEnabled {
				cancel()
				<-done
				m.mu.Lock()
				m.running, m.live = false, map[string]liveStream{}
				m.mu.Unlock()
				return errors.New("switched off")
			}
			m.reconcile()
		case <-tick.C:
			if err := m.poll(); err == nil {
				m.mu.Lock()
				if !m.running {
					first = true
				}
				m.running = true
				m.status = "running"
				m.mu.Unlock()
				if first {
					first = false
					m.reconcile()
				}
			}
		}
	}
}

func (m *Media) api(method, path string, body any, out any) error {
	m.mu.Lock()
	base := m.apiBase
	m.mu.Unlock()
	if base == "" {
		return errors.New("video server not running")
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		json.Unmarshal(b, &e)
		return fmt.Errorf("MediaMTX %s %s: %d %s", method, path, resp.StatusCode, e.Error)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (m *Media) poll() error {
	var res struct {
		Items []struct {
			Name   string `json:"name"`
			Ready  bool   `json:"ready"`
			Source *struct {
				Type string `json:"type"`
			} `json:"source"`
			ReadyTime     *time.Time `json:"readyTime"`
			Tracks        []string   `json:"tracks"`
			BytesReceived uint64     `json:"bytesReceived"`
			Readers       []any      `json:"readers"`
		} `json:"items"`
	}
	if err := m.api("GET", "/v3/paths/list?itemsPerPage=1000", nil, &res); err != nil {
		return err
	}
	live := map[string]liveStream{}
	for _, it := range res.Items {
		ls := liveStream{Name: it.Name, Ready: it.Ready, Tracks: it.Tracks, BytesIn: it.BytesReceived, Readers: len(it.Readers)}
		if it.Source != nil {
			ls.Source = it.Source.Type
		}
		if it.ReadyTime != nil {
			ls.ReadySince = *it.ReadyTime
		}
		live[it.Name] = ls
	}
	m.mu.Lock()
	m.live = live
	m.mu.Unlock()
	return nil
}

// reconcile brings the pulled streams in MediaMTX in line with the wanted list.
func (m *Media) reconcile() {
	var conf struct {
		Items []struct {
			Name          string `json:"name"`
			Source        string `json:"source"`
			RTSPTransport string `json:"rtspTransport"`
		} `json:"items"`
	}
	if err := m.api("GET", "/v3/config/paths/list?itemsPerPage=1000", nil, &conf); err != nil {
		return
	}
	have := map[string]string{}
	for _, it := range conf.Items {
		if it.Name != "all_others" {
			have[it.Name] = it.Source
		}
	}
	want := map[string]bool{}
	for _, d := range m.desired() {
		want[d.Name] = true
		body := map[string]any{"source": d.Source, "sourceOnDemand": true}
		if d.TCP {
			body["rtspTransport"] = "tcp"
		}
		src, ok := have[d.Name]
		var err error
		switch {
		case !ok:
			err = m.api("POST", "/v3/config/paths/add/"+d.Name, body, nil)
		case src != d.Source:
			err = m.api("PATCH", "/v3/config/paths/patch/"+d.Name, body, nil)
		}
		if err != nil {
			logf("Video: %v", err)
		}
	}
	for name := range have {
		if !want[name] {
			if err := m.api("DELETE", "/v3/config/paths/delete/"+name, nil, nil); err != nil {
				logf("Video: %v", err)
			}
		}
	}
	m.writeConfig(filepath.Join(m.srv.dataDir, "mediamtx", "mediamtx.yml")) // same list after a restart
}

// SetAuto replaces the automatic streams of one owner (federation link or bridge).
func (m *Media) SetAuto(owner string, paths []autoPath) {
	m.mu.Lock()
	old := m.auto[owner]
	changed := len(old) != len(paths)
	next := map[string]autoPath{}
	for _, p := range paths {
		next[p.Name] = p
		if o, ok := old[p.Name]; !ok || o != p {
			changed = true
		}
	}
	if len(paths) == 0 {
		delete(m.auto, owner)
	} else {
		m.auto[owner] = next
	}
	m.mu.Unlock()
	if changed {
		m.Kick()
	}
}

// autoTaken: is the name already used by another owner with fewer hops?
func (m *Media) autoTaken(name, owner string, hops int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for o, paths := range m.auto {
		if o == owner {
			continue
		}
		if p, ok := paths[name]; ok && p.Hops <= hops {
			return true
		}
	}
	return false
}

func (m *Media) Live() map[string]liveStream {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]liveStream, len(m.live))
	for k, v := range m.live {
		out[k] = v
	}
	return out
}

func (m *Media) autoPaths() []autoPath {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []autoPath
	for _, paths := range m.auto {
		for _, p := range paths {
			out = append(out, p)
		}
	}
	return out
}

// ---------- logins (called by MediaMTX for every publish/read) ----------

func (m *Media) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("key") != m.key {
		http.Error(w, "forbidden", 403)
		return
	}
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
		Token    string `json:"token"`
		IP       string `json:"ip"`
		Action   string `json:"action"`
		Path     string `json:"path"`
		Protocol string `json:"protocol"`
		Query    string `json:"query"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req)
	ip := net.ParseIP(req.IP)
	local := ip != nil && ip.IsLoopback()
	allow := func(ok bool) {
		if ok {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}
	switch req.Action {
	case "api", "metrics", "pprof":
		allow(local)
		return
	}
	user, pass := req.User, req.Password
	q, _ := url.ParseQuery(req.Query)
	if user == "" {
		user, pass = q.Get("user"), q.Get("pass")
	}
	tok := req.Token
	if tok == "" {
		tok = q.Get("token")
	}
	if tok == "" {
		tok = q.Get("jwt")
	}
	// a federated server pulling one of our streams through the tunnel logs in with the link secret
	if strings.HasPrefix(user, "fed-") && (req.Action == "read" || req.Action == "playback") {
		allow(m.srv.fedVideoLogin(strings.TrimPrefix(user, "fed-"), pass))
		return
	}
	loggedIn := (user != "" && m.srv.checkLogin(user, pass, false)) || (tok != "" && m.srv.videoToken(tok))
	switch req.Action {
	case "publish":
		if strings.HasPrefix(req.Path, "fed-") || strings.HasPrefix(req.Path, "ots-") {
			allow(false) // reserved for linked servers
			return
		}
		allow(loggedIn)
	case "read", "playback":
		allow(loggedIn || !m.srv.store.Config().VideoReadAuth)
	default:
		allow(false)
	}
}

func (s *Server) fedVideoLogin(peerUID, secret string) bool {
	ok := false
	s.store.Read(func(st *State) {
		for _, l := range st.FedLinks {
			if l.PeerUID == peerUID && l.Enabled && l.Secret != "" && l.Secret == secret {
				ok = true
			}
		}
	})
	return ok
}

// videoToken: API token of an active user, or the token of a federation/bridge video share.
func (s *Server) videoToken(tok string) bool {
	ok := false
	s.store.Read(func(st *State) {
		for _, u := range st.Users {
			if u.Active && u.APIToken != "" && u.APIToken == tok {
				ok = true
			}
		}
		for _, b := range st.Bridges {
			if b.ExportVideo && b.Enabled && b.UID != "" && tok == bridgeVideoToken(b) {
				ok = true
			}
		}
	})
	return ok
}

func bridgeVideoToken(b *Bridge) string {
	h := sha1.Sum([]byte("video:" + b.ID + ":" + b.Password + ":" + b.UID))
	return hex.EncodeToString(h[:12])
}

// ---------- the list of feeds shown to devices and in the web interface ----------

type Feed struct {
	UID        string   `json:"uid"`
	Alias      string   `json:"alias"`
	Path       string   `json:"path,omitempty"` // stream on this server
	Kind       string   `json:"kind"`           // pushed, pulled, federation, bridge, link
	Source     string   `json:"source,omitempty"`
	Origin     string   `json:"origin,omitempty"`
	URL        string   `json:"url,omitempty"` // link-only feeds
	Live       bool     `json:"live"`
	Readers    int      `json:"readers"`
	Tracks     []string `json:"tracks,omitempty"`
	User       string   `json:"user,omitempty"`
	Configured bool     `json:"configured"`
}

func stableUID(s string) string {
	h := sha1.Sum([]byte(s))
	x := hex.EncodeToString(h[:16])
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

func (m *Media) Feeds() []Feed {
	live := m.Live()
	seen := map[string]bool{}
	var out []Feed
	m.srv.store.Read(func(s *State) {
		for _, f := range s.Videos {
			if f.Path == "" {
				out = append(out, Feed{UID: f.UID, Alias: f.Alias, Kind: "link", URL: f.URL, Configured: true, User: f.User})
				continue
			}
			seen[f.Path] = true
			kind := "pushed"
			if f.Source != "" {
				kind = "pulled"
			}
			l := live[f.Path]
			out = append(out, Feed{UID: f.UID, Alias: f.Alias, Path: f.Path, Kind: kind, Source: redactURL(f.Source), Live: l.Ready,
				Readers: l.Readers, Tracks: l.Tracks, Configured: true, User: f.User})
		}
	})
	for _, a := range m.autoPaths() {
		if seen[a.Name] {
			continue
		}
		seen[a.Name] = true
		kind := "federation"
		if strings.HasPrefix(a.Owner, "bridge:") {
			kind = "bridge"
		}
		l := live[a.Name]
		out = append(out, Feed{UID: stableUID(a.Name), Alias: a.OriginName + ": " + a.Alias, Path: a.Name, Kind: kind,
			Origin: a.OriginName, Live: l.Ready, Readers: l.Readers, Tracks: l.Tracks})
	}
	names := make([]string, 0, len(live))
	for n := range live {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		l := live[n]
		if seen[n] || !l.Ready {
			continue
		}
		alias := n
		if i := strings.LastIndex(n, "/"); i >= 0 {
			alias = n[i+1:]
		}
		out = append(out, Feed{UID: stableUID(n), Alias: alias, Path: n, Kind: "pushed", Live: true, Readers: l.Readers, Tracks: l.Tracks})
	}
	return out
}

func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = url.User(u.User.Username())
	return u.String()
}

// Links for a stream on this server, as seen from host.
func (s *Server) streamLinks(host, path string) map[string]string {
	p := s.ports
	out := map[string]string{}
	if p.RTSP > 0 {
		out["rtsp"] = fmt.Sprintf("rtsp://%s/%s", joinHostPort(host, p.RTSP), path)
	}
	if p.HLS > 0 {
		out["hls"] = fmt.Sprintf("http://%s/%s/index.m3u8", joinHostPort(host, p.HLS), path)
	}
	if p.WebRTC > 0 {
		out["webrtc"] = fmt.Sprintf("http://%s/%s/", joinHostPort(host, p.WebRTC), path)
	}
	return out
}

// Addresses cameras / drones / OBS publish to (user and password of a TAK user).
func (s *Server) publishLinks(host, path, user string) map[string]string {
	p := s.ports
	out := map[string]string{}
	u := urlQuery(user)
	if p.RTMP > 0 {
		out["rtmp"] = fmt.Sprintf("rtmp://%s/%s?user=%s&pass=PASSWORD", joinHostPort(host, p.RTMP), path, u)
	}
	if p.RTSP > 0 {
		out["rtsp"] = fmt.Sprintf("rtsp://%s:PASSWORD@%s/%s", u, joinHostPort(host, p.RTSP), path)
	}
	if p.SRT > 0 {
		out["srt"] = fmt.Sprintf("srt://%s?streamid=publish:%s:%s:PASSWORD", joinHostPort(host, p.SRT), path, u)
	}
	return out
}

var rePathChars = regexp.MustCompile(`[^A-Za-z0-9_.~-]+`)

func slugPath(s string) string {
	parts := strings.Split(strings.Trim(s, "/"), "/")
	var out []string
	for _, p := range parts {
		p = strings.Trim(rePathChars.ReplaceAllString(p, "-"), "-.")
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "/")
}

// slugName: lower-case name for automatic path prefixes (fed-<server>, ots-<server>)
func slugName(s string) string {
	s = strings.ToLower(strings.ReplaceAll(slugPath(s), "/", "-"))
	if s == "" {
		s = "server"
	}
	return s
}

func validPath(p string) bool {
	return p != "" && p == slugPath(p) && len(p) <= 120 && p != "all_others"
}

func itoa(i int) string { return strconv.Itoa(i) }

// SaveStream adds or changes a stream on the video server. source empty = cameras push to it.
func (s *Server) SaveStream(path, source, alias, user string, mustExist bool) error {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, "/") {
		return errors.New("path cannot begin with a slash")
	}
	if !validPath(path) {
		return errors.New("path: letters, digits and - _ . / only, e.g. drone-1 or cam/alpha")
	}
	if strings.HasPrefix(path, "fed-") || strings.HasPrefix(path, "ots-") {
		return errors.New("paths starting with fed- or ots- are reserved for linked servers")
	}
	source = strings.TrimSpace(source)
	if source != "" {
		u, err := url.Parse(source)
		if err != nil || u.Scheme == "" {
			return errors.New("source must be an address like rtsp://…, rtmp://…, srt://…, udp://… or https://…/index.m3u8")
		}
	}
	var err error
	s.store.Update(func(st *State) {
		for _, v := range st.Videos {
			if v.Path == path {
				v.Source = source
				if alias != "" {
					v.Alias = alias
				}
				return
			}
		}
		if mustExist {
			err = fmt.Errorf("path %s not found", path)
			return
		}
		st.Videos = append(st.Videos, &VideoFeed{UID: newUUID(), Alias: orDefault(alias, path), Path: path, Source: source, User: user, Created: time.Now()})
	})
	if err == nil {
		s.media.Kick()
	}
	return err
}

func (s *Server) DeleteStream(path string) bool {
	found := false
	s.store.Update(func(st *State) {
		keep := st.Videos[:0]
		for _, v := range st.Videos {
			if v.Path == path && path != "" {
				found = true
				continue
			}
			keep = append(keep, v)
		}
		st.Videos = keep
	})
	if found {
		s.media.Kick()
	}
	return found
}

func (s *Server) streamOwnedBy(path, user string) bool {
	ok := false
	s.store.Read(func(st *State) {
		for _, v := range st.Videos {
			if v.Path == path && v.User == user {
				ok = true
			}
		}
	})
	return ok
}
