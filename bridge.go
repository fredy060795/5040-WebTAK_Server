package main

// Bridge to another TAK server: OpenTAKServer (which has no server-to-server federation),
// TAK Server or FreeTAKServer. WebTAK Server connects to it like a device – with a user of that
// server and a certificate it enrolls for itself – and relays in both directions:
//
//   devices of the other server  <──>  bridge  <──>  devices here and on all federated WebTAK Servers
//
// Video: feeds of the other server can be shown here (pulled on demand from its MediaMTX), and our
// feeds can be registered on an OpenTAKServer (its MediaMTX then pulls them from us).

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// how often the video lists are compared with the other server
var bridgeVideoInterval = time.Minute

type bridgeConn struct {
	br        *Bridges
	mu        sync.RWMutex
	b         Bridge
	conn      net.Conn
	send      chan []byte
	closed    chan struct{}
	once      sync.Once
	connected time.Time
	rx, tx    atomic.Int64
}

func (c *bridgeConn) sourceID() string { return "bridge:" + c.get().ID }

func (c *bridgeConn) get() Bridge {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.b
}

func (c *bridgeConn) localGroups() []string {
	if g := c.get().Groups; len(g) > 0 {
		return g
	}
	return nil
}

func (c *bridgeConn) Close() {
	c.once.Do(func() {
		close(c.closed)
		c.conn.Close()
	})
}

func (c *bridgeConn) enqueue(b []byte) {
	select {
	case c.send <- b:
	case <-c.closed:
	default:
		logf("Bridge %s: send queue full – reconnecting", c.get().Name)
		c.Close()
	}
}

type Bridges struct {
	srv    *Server
	mu     sync.Mutex
	conns  map[string]*bridgeConn
	status map[string]string
	loops  map[string]chan struct{}
	stop   chan struct{}
	wg     sync.WaitGroup
}

func NewBridges(srv *Server) *Bridges {
	return &Bridges{srv: srv, conns: map[string]*bridgeConn{}, status: map[string]string{}, loops: map[string]chan struct{}{}, stop: make(chan struct{})}
}

func (br *Bridges) Start() { br.Reconcile() }

func (br *Bridges) Stop() {
	close(br.stop)
	br.mu.Lock()
	for _, ch := range br.loops {
		close(ch)
	}
	br.loops = map[string]chan struct{}{}
	var conns []*bridgeConn
	for _, c := range br.conns {
		conns = append(conns, c)
	}
	br.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	br.wg.Wait()
}

func (br *Bridges) list() []Bridge {
	var out []Bridge
	br.srv.store.Read(func(s *State) {
		for _, b := range s.Bridges {
			out = append(out, *b)
		}
	})
	return out
}

func (br *Bridges) Reconcile() {
	select {
	case <-br.stop:
		return
	default:
	}
	byID := map[string]Bridge{}
	for _, b := range br.list() {
		byID[b.ID] = b
	}
	br.mu.Lock()
	defer br.mu.Unlock()
	for id, c := range br.conns {
		b, ok := byID[id]
		if !ok || !b.Enabled {
			go c.Close()
			continue
		}
		c.mu.Lock()
		c.b.Groups, c.b.ImportVideo, c.b.ExportVideo, c.b.Name = b.Groups, b.ImportVideo, b.ExportVideo, b.Name
		c.mu.Unlock()
	}
	for id, ch := range br.loops {
		if b, ok := byID[id]; !ok || !b.Enabled {
			close(ch)
			delete(br.loops, id)
			br.srv.media.SetAuto("bridge:"+id, nil)
		}
	}
	for id, b := range byID {
		if b.Enabled && br.loops[id] == nil {
			ch := make(chan struct{})
			br.loops[id] = ch
			br.wg.Add(1)
			go br.loop(id, ch)
		}
	}
}

func (br *Bridges) setStatus(id, s string) {
	br.mu.Lock()
	br.status[id] = s
	br.mu.Unlock()
}

func (br *Bridges) name(id string) string {
	for _, b := range br.list() {
		if b.ID == id {
			return b.Name
		}
	}
	return id
}

// ---------- setting up a bridge ----------

type BridgeInput struct {
	Name, Host, Username, Password string
	TLS                            bool
	StreamPort, EnrollPort         int
	APIPort, WebPort, RTSPPort     int
	ImportVideo, ExportVideo       bool
}

// Add enrolls a certificate on the other server (SSL) and saves the bridge.
func (br *Bridges) Add(in BridgeInput) (*Bridge, error) {
	in.Host = strings.TrimSpace(in.Host)
	for _, p := range []string{"https://", "http://", "ssl://", "tcp://"} {
		in.Host = strings.TrimPrefix(in.Host, p)
	}
	in.Host = strings.TrimRight(in.Host, "/")
	if h, _, err := net.SplitHostPort(in.Host); err == nil {
		in.Host = h
	}
	if in.Host == "" {
		return nil, errors.New("please enter the address of the other TAK server")
	}
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	if in.TLS {
		def(&in.StreamPort, 8089)
	} else {
		def(&in.StreamPort, 8088)
	}
	def(&in.EnrollPort, 8446)
	def(&in.APIPort, 8443)
	def(&in.WebPort, 443)
	def(&in.RTSPPort, 8554)
	cfg := br.srv.store.Config()
	b := &Bridge{ID: randomHex(6), Name: strings.TrimSpace(in.Name), Host: in.Host, StreamPort: in.StreamPort, EnrollPort: in.EnrollPort,
		APIPort: in.APIPort, WebPort: in.WebPort, RTSPPort: in.RTSPPort, TLS: in.TLS, Username: strings.TrimSpace(in.Username),
		Password: in.Password, UID: "WebTAK-Server-" + cfg.ServerUID + "-" + randomHex(3), Callsign: cfg.ServerName + " (WebTAK)",
		Enabled: true, ImportVideo: in.ImportVideo, ExportVideo: in.ExportVideo, Created: time.Now()}
	if b.Name == "" {
		b.Name = b.Host
	}
	if b.TLS {
		if b.Username == "" || b.Password == "" {
			return nil, errors.New("SSL needs a user name and password of the other server (create a user there for this bridge)")
		}
		if err := enrollBridge(b); err != nil {
			return nil, err
		}
	}
	// connection test before saving
	conn, err := dialBridge(b)
	if err != nil {
		return nil, err
	}
	conn.Close()
	br.srv.store.Update(func(s *State) { s.Bridges = append(s.Bridges, b) })
	logf("Bridge to %s (%s) added", b.Name, b.Host)
	br.Reconcile()
	c := *b
	return &c, nil
}

func insecureClient(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{InsecureSkipVerify: true}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, Proxy: nil}}
}

func pemBody(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

// enrollBridge requests a client certificate like ATAK does (port 8446, user + password).
func enrollBridge(b *Bridge) error {
	base := "https://" + joinHostPort(b.Host, b.EnrollPort)
	hc := insecureClient(nil)
	req, _ := http.NewRequest("GET", base+"/Marti/api/tls/config", nil)
	req.SetBasicAuth(b.Username, b.Password)
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("enrollment port %d not reachable: %v", b.EnrollPort, shortErr(err))
	}
	cfgXML, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return errors.New("the other server rejected the user name or password")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("certificate configuration: HTTP %d", resp.StatusCode)
	}
	subj := pkix.Name{CommonName: b.Username}
	var tc struct {
		Entries []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:"value,attr"`
		} `xml:"nameEntries>nameEntry"`
	}
	xml.Unmarshal(cfgXML, &tc)
	for _, e := range tc.Entries {
		switch e.Name {
		case "O":
			subj.Organization = []string{e.Value}
		case "OU":
			subj.OrganizationalUnit = []string{e.Value}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subj}, key)
	if err != nil {
		return err
	}
	// bare base64 like ATAK (OpenTAKServer adds the PEM header and footer itself)
	q := url.Values{"clientUid": {b.UID}, "version": {"WebTAK-Server-" + Version}}
	req, _ = http.NewRequest("POST", base+"/Marti/api/tls/signClient/v2?"+q.Encode(), bytes.NewReader(pemBody(csr)))
	req.SetBasicAuth(b.Username, b.Password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "text/plain")
	resp, err = hc.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("the other server did not sign the certificate: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var signed string
	var cas []string
	var js map[string]string
	if json.Unmarshal(body, &js) == nil && js["signedCert"] != "" {
		signed = js["signedCert"]
		for k, v := range js {
			if strings.HasPrefix(k, "ca") {
				cas = append(cas, v)
			}
		}
	} else {
		var x struct {
			Signed string   `xml:"signedCert"`
			CA     []string `xml:"ca"`
		}
		if xml.Unmarshal(body, &x) != nil || x.Signed == "" {
			return errors.New("unexpected enrollment answer from the other server")
		}
		signed, cas = x.Signed, x.CA
	}
	certDER, err := decodeCertText(signed)
	if err != nil {
		return err
	}
	if _, err := x509.ParseCertificate(certDER); err != nil {
		return err
	}
	var caPEM []byte
	seen := map[string]bool{}
	for _, c := range cas {
		der, err := decodeCertText(c)
		if err != nil || seen[string(der)] {
			continue
		}
		seen[string(der)] = true
		caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	b.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	b.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	b.CAPEM = string(caPEM)
	return nil
}

// decodeCertText reads a certificate as PEM, or as a PEM body without header lines.
func decodeCertText(s string) ([]byte, error) {
	if blk, _ := pem.Decode([]byte(s)); blk != nil {
		return blk.Bytes, nil
	}
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.DecodeString(clean)
}

func (b *Bridge) tlsConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(b.CertPEM), []byte(b.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("bridge certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pinned := pool.AppendCertsFromPEM([]byte(b.CAPEM))
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // the server certificate is checked against the enrolled CA below (names vary)
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if !pinned {
				return nil
			}
			certs := make([]*x509.Certificate, 0, len(raw))
			for _, r := range raw {
				c, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				certs = append(certs, c)
			}
			inter := x509.NewCertPool()
			for _, c := range certs[1:] {
				inter.AddCert(c)
			}
			_, err := certs[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			if err != nil {
				return errors.New("the other server's certificate does not belong to its CA (new installation? remove and add the bridge again)")
			}
			return nil
		},
	}, nil
}

func dialBridge(b *Bridge) (net.Conn, error) {
	addr := joinHostPort(b.Host, b.StreamPort)
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !b.TLS {
		c, err := d.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("%s not reachable: %v", addr, shortErr(err))
		}
		return c, nil
	}
	cfg, err := b.tlsConfig()
	if err != nil {
		return nil, err
	}
	c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("SSL connection to %s failed: %v", addr, shortErr(err))
	}
	return c, nil
}

// ---------- running connection ----------

func (br *Bridges) loop(id string, stop chan struct{}) {
	defer br.wg.Done()
	backoff := 3 * time.Second
	for {
		var b *Bridge
		br.srv.store.Read(func(s *State) {
			for _, x := range s.Bridges {
				if x.ID == id {
					c := *x
					b = &c
				}
			}
		})
		if b == nil || !b.Enabled {
			return
		}
		conn, err := dialBridge(b)
		if err != nil {
			br.setStatus(id, err.Error())
		} else {
			backoff = 3 * time.Second
			br.session(conn, *b, stop)
		}
		select {
		case <-stop:
			return
		case <-br.stop:
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func (br *Bridges) selfSA(b Bridge) []byte {
	cfg := br.srv.store.Config()
	now := time.Now()
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><event version="2.0" uid="%s" type="a-f-G-I" how="h-g-i-g-o" time="%s" start="%s" stale="%s"><point lat="%f" lon="%f" hae="0" ce="9999999" le="9999999"/><detail><takv device="WebTAK Server" platform="WebTAK-Server" os="%s" version="%s"/><contact callsign="%s" endpoint="*:-1:stcp"/><__group name="Cyan" role="HQ"/><remarks>Bridge to %s – devices of that server appear here</remarks></detail></event>`,
		xmlEscape(b.UID), cotTime(now), cotTime(now), cotTime(now.Add(3*time.Minute)), cfg.Lat, cfg.Lon, runtime.GOOS, Version,
		xmlEscape(b.Callsign), xmlEscape(cfg.ServerName)))
}

func (br *Bridges) session(conn net.Conn, b Bridge, stop chan struct{}) {
	c := &bridgeConn{br: br, b: b, conn: conn, send: make(chan []byte, 4096), closed: make(chan struct{}), connected: time.Now()}
	br.mu.Lock()
	if old := br.conns[b.ID]; old != nil {
		old.Close()
	}
	br.conns[b.ID] = c
	br.status[b.ID] = ""
	br.mu.Unlock()
	logf("Bridge: connected to %s (%s)", b.Name, conn.RemoteAddr())

	go func() { // writer
		for {
			select {
			case p := <-c.send:
				conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := conn.Write(p); err != nil {
					c.Close()
					return
				}
				c.tx.Add(1)
			case <-c.closed:
				return
			}
		}
	}()
	// OpenTAKServer registers a client by its first position report – ours goes first
	c.enqueue(br.selfSA(b))
	for _, raw := range br.srv.hub.LatestForFederation(c.sourceID()) {
		if ev, err := ParseEvent(raw); err == nil {
			br.sendTo(c, raw, ev, nil, true)
		}
	}
	go func() { // keep-alive, own position, video lists
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		vt := time.NewTicker(bridgeVideoInterval)
		defer vt.Stop()
		n := 0
		br.syncVideo(c)
		for {
			select {
			case <-c.closed:
				return
			case <-stop:
				c.Close()
				return
			case <-vt.C:
				br.syncVideo(c)
			case <-t.C:
				n++
				now := time.Now()
				c.enqueue([]byte(fmt.Sprintf(`<event version="2.0" uid="%s-ping" type="t-x-c-t" how="h-g-i-g-o" time="%s" start="%s" stale="%s"><point lat="0" lon="0" hae="0" ce="9999999" le="9999999"/><detail/></event>`,
					xmlEscape(c.get().UID), cotTime(now), cotTime(now), cotTime(now.Add(time.Minute)))))
				if n%2 == 0 {
					c.enqueue(br.selfSA(c.get()))
				}
			}
		}
	}()
	er := NewEventReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(150 * time.Second))
		raw, err := er.Next()
		if err != nil {
			break
		}
		c.rx.Add(1)
		ev, err := ParseEvent(raw)
		if err != nil || ev.Type == "t-x-c-t-r" || ev.Type == "t-x-c-t" || ev.UID == b.UID {
			continue
		}
		br.srv.hub.FromFederation(c, raw)
	}
	c.Close()
	br.mu.Lock()
	if br.conns[b.ID] == c {
		delete(br.conns, b.ID)
		br.status[b.ID] = "disconnected"
	}
	br.mu.Unlock()
	logf("Bridge: disconnected from %s", b.Name)
}

// Broadcast relays an event to all connected TAK server bridges.
func (br *Bridges) Broadcast(raw []byte, ev *Event, viaSource string, groups []string) {
	br.mu.Lock()
	var conns []*bridgeConn
	for _, c := range br.conns {
		if c.sourceID() != viaSource {
			conns = append(conns, c)
		}
	}
	br.mu.Unlock()
	for _, c := range conns {
		br.sendTo(c, raw, ev, groups, viaSource == "")
	}
}

func (br *Bridges) sendTo(c *bridgeConn, raw []byte, ev *Event, groups []string, local bool) {
	b := c.get()
	if len(b.Groups) > 0 && len(groups) > 0 && !intersects(groups, b.Groups) {
		return
	}
	c.enqueue(AddFlowTag(raw, br.srv.hub.fedTag()))
}

// ---------- video with the other server ----------

type vcmFeed struct {
	Protocol string `xml:"protocol"`
	Alias    string `xml:"alias"`
	UID      string `xml:"uid"`
	Address  string `xml:"address"`
	Port     string `xml:"port"`
	Path     string `xml:"path"`
	URL      string `xml:"url"`
}

func (br *Bridges) syncVideo(c *bridgeConn) {
	b := c.get()
	owner := "bridge:" + b.ID
	if !br.srv.store.Config().VideoEnabled {
		return
	}
	if b.ImportVideo {
		feeds, err := br.fetchFeeds(b)
		if err != nil {
			br.setStatus(b.ID, "video list: "+err.Error())
		}
		var paths []autoPath
		prefix := "ots-" + slugName(b.Name)
		ownPrefix := "wts-" + slugName(br.srv.store.Config().ServerName) + "/"
		for _, f := range feeds {
			p := strings.TrimPrefix(f.Path, "/")
			if f.URL != "" && p == "" {
				if u, err := url.Parse(f.URL); err == nil {
					p = strings.TrimPrefix(u.Path, "/")
				}
			}
			if p == "" || strings.HasPrefix(p, ownPrefix) {
				continue // our own streams registered there
			}
			port := b.RTSPPort
			if n, err := strconv.Atoi(f.Port); err == nil && n > 0 && (f.Protocol == "" || f.Protocol == "rtsp") {
				port = n
			}
			src := "rtsp://"
			if b.Username != "" {
				src += url.UserPassword(b.Username, b.Password).String() + "@"
			}
			src += joinHostPort(b.Host, port) + "/" + p
			alias := f.Alias
			if alias == "" {
				alias = p
			}
			name := prefix + "/" + slugPath(p)
			paths = append(paths, autoPath{Name: name, Source: src, Alias: alias, Origin: owner, OriginName: b.Name, OPath: p, Owner: owner})
		}
		br.srv.media.SetAuto(owner, paths)
	} else {
		br.srv.media.SetAuto(owner, nil)
	}
	if b.ExportVideo {
		if err := br.exportVideo(b); err != nil {
			br.setStatus(b.ID, "sharing video: "+err.Error())
		}
	}
}

// fetchFeeds reads the video list of the other server (/Marti/vcm like ATAK).
func (br *Bridges) fetchFeeds(b Bridge) ([]vcmFeed, error) {
	var urls []string
	var hc *http.Client
	if b.TLS {
		cert, err := tls.X509KeyPair([]byte(b.CertPEM), []byte(b.KeyPEM))
		if err != nil {
			return nil, err
		}
		hc = insecureClient(&cert)
		urls = append(urls, "https://"+joinHostPort(b.Host, b.APIPort)+"/Marti/vcm")
	} else {
		hc = insecureClient(nil)
	}
	urls = append(urls, "http://"+joinHostPort(b.Host, 8080)+"/Marti/vcm")
	var lastErr error
	for _, u := range urls {
		req, _ := http.NewRequest("GET", u, nil)
		if b.Username != "" {
			req.SetBasicAuth(b.Username, b.Password)
		}
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		var v struct {
			Feeds []vcmFeed `xml:"feed"`
		}
		if err := xml.Unmarshal(body, &v); err != nil {
			lastErr = err
			continue
		}
		return v.Feeds, nil
	}
	return nil, lastErr
}

// exportVideo registers our feeds on an OpenTAKServer (its MediaMTX pulls them from us on demand).
func (br *Bridges) exportVideo(b Bridge) error {
	base := "https://" + joinHostPort(b.Host, b.WebPort)
	hc := insecureClient(nil)
	body, _ := json.Marshal(map[string]string{"username": b.Username, "password": b.Password})
	resp, err := hc.Post(base+"/api/login?include_auth_token", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("OTS web port %d not reachable", b.WebPort)
	}
	var lr struct {
		Response struct {
			User struct {
				Token string `json:"authentication_token"`
			} `json:"user"`
		} `json:"response"`
	}
	json.NewDecoder(resp.Body).Decode(&lr)
	resp.Body.Close()
	tok := lr.Response.User.Token
	if resp.StatusCode != 200 || tok == "" {
		return errors.New("OTS login for sharing video failed")
	}
	call := func(method, path string, payload any) (*http.Response, error) {
		var rd io.Reader
		if payload != nil {
			pb, _ := json.Marshal(payload)
			rd = bytes.NewReader(pb)
		}
		req, _ := http.NewRequest(method, base+path, rd)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authentication-Token", tok)
		return hc.Do(req)
	}
	cfg := br.srv.store.Config()
	prefix := "wts-" + slugName(cfg.ServerName) + "/"
	host := br.srv.PublicHost()
	vtok := bridgeVideoToken(&b)
	want := map[string]string{}
	for _, f := range br.srv.media.Feeds() {
		if f.Path == "" || (f.Kind == "pushed" && !f.Live) || strings.HasPrefix(f.Path, "ots-"+slugName(b.Name)+"/") {
			continue
		}
		want[prefix+f.Path] = fmt.Sprintf("rtsp://%s/%s?token=%s", joinHostPort(host, br.srv.ports.RTSP), f.Path, vtok)
	}
	have := map[string]string{}
	if r, err := call("GET", "/api/video_streams?per_page=500", nil); err == nil {
		var list struct {
			Results []struct {
				Path     string `json:"path"`
				Settings string `json:"mediamtx_settings"`
			} `json:"results"`
		}
		json.NewDecoder(r.Body).Decode(&list)
		r.Body.Close()
		for _, v := range list.Results {
			if strings.HasPrefix(v.Path, prefix) {
				var st struct{ Source string }
				json.Unmarshal([]byte(v.Settings), &st)
				have[v.Path] = st.Source
			}
		}
	}
	for p, src := range want {
		if old, ok := have[p]; ok && old == src {
			continue
		}
		method, ep := "POST", "/api/mediamtx/stream/add"
		if _, ok := have[p]; ok {
			method, ep = "PATCH", "/api/mediamtx/stream/update"
		}
		r, err := call(method, ep, map[string]any{"path": p, "source": src, "sourceOnDemand": true})
		if err != nil {
			return err
		}
		r.Body.Close()
		if r.StatusCode >= 300 {
			return fmt.Errorf("OTS refused stream %s (HTTP %d)", p, r.StatusCode)
		}
	}
	for p := range have {
		if _, ok := want[p]; !ok {
			if r, err := call("DELETE", "/api/mediamtx/stream/delete?path="+url.QueryEscape(p), nil); err == nil {
				r.Body.Close()
			}
		}
	}
	return nil
}

// ---------- status for the web interface ----------

func (br *Bridges) Status() []map[string]any {
	list := br.list()
	br.mu.Lock()
	defer br.mu.Unlock()
	out := []map[string]any{}
	for _, b := range list {
		m := map[string]any{"id": b.ID, "name": b.Name, "host": b.Host, "streamPort": b.StreamPort, "tls": b.TLS, "username": b.Username,
			"enabled": b.Enabled, "groups": b.Groups, "importVideo": b.ImportVideo, "exportVideo": b.ExportVideo, "callsign": b.Callsign,
			"connected": false, "error": br.status[b.ID]}
		if c := br.conns[b.ID]; c != nil {
			m["connected"], m["since"], m["rx"], m["tx"] = true, c.connected, c.rx.Load(), c.tx.Load()
			if strings.HasPrefix(br.status[b.ID], "disconnected") {
				m["error"] = ""
			}
		}
		out = append(out, m)
	}
	return out
}
