package main

// Federation: link several WebTAK servers so their devices see each other (positions, markers,
// chat, data packages) – in both directions over one TLS connection.
//
// Pairing: server A creates an invite code (addresses, one-time token, fingerprint of A's CA).
// Server B pastes it and connects. A checks the token, both sides pin each other's CA and agree on a
// link secret for later reconnects. Only B needs to reach A (B may be behind NAT / mobile network).
//
// Chains (A–B–C) work: events are forwarded with flow tags so nothing loops.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const fedProto = "webtak-fed/1"

const (
	fHello byte = iota + 1
	fHelloOK
	fCoT
	fFileMeta
	fFileChunk
	fFileEnd
	fPing
	fPong
	fError
	fFeeds       // video feeds this server offers (JSON)
	fStreamOpen  // tunnel: open a connection to the video server (id)
	fStreamData  // tunnel: data (id + bytes)
	fStreamClose // tunnel: close (id)
)

const (
	maxFrame       = 16 << 20
	fedFileLimit   = 250 << 20
	fedChunk       = 256 << 10
	invitePrefix   = "WTS1-"
	inviteLifetime = 7 * 24 * time.Hour
)

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(append(hdr, payload...)); err != nil {
		return err
	}
	return nil
}

func readFrame(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("frame too large (%d bytes)", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return hdr[0], b, nil
}

type helloMsg struct {
	Proto   string `json:"proto"`
	UID     string `json:"uid"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Secret  string `json:"secret,omitempty"`
	Invite  string `json:"invite,omitempty"`
}

type helloOK struct {
	UID    string `json:"uid"`
	Name   string `json:"name"`
	Secret string `json:"secret,omitempty"` // new link secret after redeeming an invite
}

type inviteData struct {
	Name      string   `json:"n"`
	UID       string   `json:"u"`
	Addresses []string `json:"a"`
	Token     string   `json:"t"`
	CAFP      string   `json:"f"`
}

type fileMeta struct {
	Hash       string   `json:"hash"`
	Name       string   `json:"name"`
	Size       int64    `json:"size"`
	MIME       string   `json:"mime"`
	Keywords   []string `json:"keywords"`
	CreatorUID string   `json:"creatorUid"`
	User       string   `json:"user"`
	Tool       string   `json:"tool"`
}

type fedItem struct {
	typ      byte
	payload  []byte
	fileHash string // stream this file instead of a frame
}

type fedConn struct {
	f         *Federation
	mu        sync.RWMutex
	link      FedLink
	conn      net.Conn
	out       chan fedItem
	closed    chan struct{}
	once      sync.Once
	connected time.Time
	remote    string
	rx, tx    atomic.Int64
	sentFiles map[string]bool
	recv      map[string]*os.File
	vt        *videoTunnel
}

func (c *fedConn) Close() {
	c.once.Do(func() {
		close(c.closed)
		c.conn.Close()
	})
}

func (c *fedConn) getLink() FedLink {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.link
}

func (c *fedConn) localGroups() []string {
	l := c.getLink()
	if len(l.Groups) == 0 {
		return nil
	}
	return l.Groups
}

func (c *fedConn) enqueue(it fedItem) {
	select {
	case c.out <- it:
	case <-c.closed:
	default:
		logf("Federation %s: send queue full – reconnecting", c.getLink().PeerName)
		c.Close()
	}
}

type Federation struct {
	srv    *Server
	mu     sync.Mutex
	conns  map[string]*fedConn
	status map[string]string
	loops  map[string]chan struct{}
	stop   chan struct{}
	wg     sync.WaitGroup
}

func NewFederation(srv *Server) *Federation {
	return &Federation{srv: srv, conns: map[string]*fedConn{}, status: map[string]string{}, loops: map[string]chan struct{}{}, stop: make(chan struct{})}
}

func (f *Federation) Start() { f.Reconcile() }

func (f *Federation) Stop() {
	close(f.stop)
	f.mu.Lock()
	for _, ch := range f.loops {
		close(ch)
	}
	f.loops = map[string]chan struct{}{}
	conns := make([]*fedConn, 0, len(f.conns))
	for _, c := range f.conns {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	f.wg.Wait()
}

func (f *Federation) setStatus(id, msg string) {
	f.mu.Lock()
	f.status[id] = msg
	f.mu.Unlock()
}

func (f *Federation) linkName(id string) string {
	name := id
	f.srv.store.Read(func(s *State) {
		for _, l := range s.FedLinks {
			if l.ID == id {
				name = l.PeerName
			}
		}
	})
	return name
}

func (f *Federation) links() []FedLink {
	var out []FedLink
	f.srv.store.Read(func(s *State) {
		for _, l := range s.FedLinks {
			out = append(out, *l)
		}
	})
	return out
}

// Reconcile starts/stops connection loops and updates running connections after link changes.
func (f *Federation) Reconcile() {
	select {
	case <-f.stop:
		return
	default:
	}
	links := f.links()
	byID := map[string]FedLink{}
	for _, l := range links {
		byID[l.ID] = l
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, c := range f.conns {
		l, ok := byID[id]
		if !ok || !l.Enabled {
			go c.Close()
			continue
		}
		c.mu.Lock()
		c.link.Groups, c.link.Transit, c.link.PeerName = l.Groups, l.Transit, l.PeerName
		c.mu.Unlock()
	}
	for id, ch := range f.loops {
		if l, ok := byID[id]; !ok || !l.Enabled {
			close(ch)
			delete(f.loops, id)
		}
	}
	for _, l := range links {
		if l.Outgoing && l.Enabled && f.loops[l.ID] == nil {
			ch := make(chan struct{})
			f.loops[l.ID] = ch
			f.wg.Add(1)
			go f.dialLoop(l.ID, ch)
		}
	}
}

// ---------- invites ----------

func (f *Federation) CreateInvite(label string) (string, error) {
	cfg := f.srv.store.Config()
	port := f.srv.ports.Fed
	if port <= 0 {
		return "", errors.New("the federation port is not open")
	}
	tok := randomHex(16)
	f.srv.store.Update(func(s *State) {
		now := time.Now()
		keep := s.FedInvites[:0]
		for _, inv := range s.FedInvites {
			if now.Before(inv.Expires) {
				keep = append(keep, inv)
			}
		}
		s.FedInvites = append(keep, &FedInvite{Token: tok, Label: label, Created: now, Expires: now.Add(inviteLifetime)})
	})
	var addrs []string
	seen := map[string]bool{}
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		a := joinHostPort(hostOnly(h), port)
		if !seen[a] {
			seen[a] = true
			addrs = append(addrs, a)
		}
	}
	add(cfg.PublicHost)
	for _, ip := range localIPs() {
		add(ip)
	}
	b, _ := json.Marshal(inviteData{Name: cfg.ServerName, UID: cfg.ServerUID, Addresses: addrs, Token: tok, CAFP: f.srv.pki.CAFingerprint()})
	return invitePrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func ParseInvite(code string) (*inviteData, error) {
	code = strings.Join(strings.Fields(code), "")
	if !strings.HasPrefix(code, invitePrefix) {
		return nil, errors.New("this is not a WebTAK Server invite code (it starts with " + invitePrefix + ")")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, invitePrefix))
	if err != nil {
		return nil, errors.New("the invite code is incomplete – copy it again")
	}
	var inv inviteData
	if err := json.Unmarshal(b, &inv); err != nil || inv.Token == "" || inv.CAFP == "" || len(inv.Addresses) == 0 {
		return nil, errors.New("the invite code is damaged – copy it again")
	}
	return &inv, nil
}

// Join redeems an invite of another server. extraAddr (optional) is tried first, e.g. a DNS name or
// ZeroTier address the other server is reachable under.
func (f *Federation) Join(code, extraAddr string) (*FedLink, error) {
	inv, err := ParseInvite(code)
	if err != nil {
		return nil, err
	}
	cfg := f.srv.store.Config()
	if inv.UID == cfg.ServerUID {
		return nil, errors.New("this invite was created by this server – open it on the other server")
	}
	addrs := inv.Addresses
	if extraAddr = strings.TrimSpace(extraAddr); extraAddr != "" {
		if _, _, err := net.SplitHostPort(extraAddr); err != nil {
			_, port, _ := net.SplitHostPort(inv.Addresses[0])
			extraAddr = net.JoinHostPort(extraAddr, port)
		}
		addrs = append([]string{extraAddr}, addrs...)
	}
	link := FedLink{ID: randomHex(6), PeerUID: inv.UID, PeerName: inv.Name, Outgoing: true, Addresses: addrs,
		Invite: inv.Token, PeerCAFP: inv.CAFP, Enabled: true, Transit: true, Created: time.Now()}
	conn, ok, err := f.dialAny(&link)
	if err != nil {
		return nil, err
	}
	// saved now with the secret received in the handshake
	link.Secret, link.Invite = ok.Secret, ""
	link.PeerName = ok.Name
	f.srv.store.Update(func(s *State) {
		keep := s.FedLinks[:0]
		for _, l := range s.FedLinks {
			if l.PeerUID != link.PeerUID {
				keep = append(keep, l)
			}
		}
		c := link
		s.FedLinks = append(keep, &c)
	})
	logf("Federation: linked with %s (%s)", link.PeerName, conn.RemoteAddr())
	f.mu.Lock()
	ch := make(chan struct{})
	if old := f.loops[link.ID]; old != nil {
		close(old)
	}
	f.loops[link.ID] = ch
	f.mu.Unlock()
	f.Reconcile() // drops an older link to the same server
	f.wg.Add(1)
	go func() {
		f.session(conn, link)
		f.dialLoop(link.ID, ch)
	}()
	return &link, nil
}

// ---------- outgoing connections ----------

func (f *Federation) clientTLS(pinnedFP string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by the pinned CA check below
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return f.srv.pki.ServerCert(), nil
		},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			fp, err := peerCAFingerprint(raw)
			if err != nil {
				return err
			}
			if !strings.EqualFold(fp, pinnedFP) {
				return errors.New("the other server's certificate does not match the invite (wrong server or new installation – create a new invite)")
			}
			return nil
		},
	}
}

// peerCAFingerprint checks that the leaf is signed by the CA sent along and returns the CA fingerprint.
func peerCAFingerprint(raw [][]byte) (string, error) {
	if len(raw) < 2 {
		return "", errors.New("the other side sent no certificate chain")
	}
	leaf, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return "", err
	}
	ca, err := x509.ParseCertificate(raw[len(raw)-1])
	if err != nil {
		return "", err
	}
	if !ca.IsCA {
		return "", errors.New("the other side's chain has no CA")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return "", errors.New("the other side's certificate is not signed by its CA")
	}
	if time.Now().After(leaf.NotAfter) {
		return "", errors.New("the other side's certificate has expired")
	}
	return certFingerprint(ca), nil
}

// dialAny tries all addresses of a link and performs the handshake.
func (f *Federation) dialAny(l *FedLink) (net.Conn, *helloOK, error) {
	var errs []string
	for _, addr := range l.Addresses {
		d := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
		conn, err := tls.DialWithDialer(d, "tcp", addr, f.clientTLS(l.PeerCAFP))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", addr, shortErr(err)))
			continue
		}
		cfg := f.srv.store.Config()
		hello := helloMsg{Proto: fedProto, UID: cfg.ServerUID, Name: cfg.ServerName, Version: Version, Secret: l.Secret, Invite: l.Invite}
		b, _ := json.Marshal(hello)
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := writeFrame(conn, fHello, b); err != nil {
			conn.Close()
			errs = append(errs, fmt.Sprintf("%s: %v", addr, err))
			continue
		}
		typ, payload, err := readFrame(conn)
		if err != nil {
			conn.Close()
			errs = append(errs, fmt.Sprintf("%s: %v", addr, shortErr(err)))
			continue
		}
		if typ == fError {
			conn.Close()
			return nil, nil, &rejectedErr{string(payload)} // the server answered: no point trying other addresses
		}
		var ok helloOK
		if typ != fHelloOK || json.Unmarshal(payload, &ok) != nil {
			conn.Close()
			errs = append(errs, addr+": unexpected answer")
			continue
		}
		if ok.UID != l.PeerUID {
			conn.Close()
			return nil, nil, errors.New("connected to a different server than expected")
		}
		conn.SetDeadline(time.Time{})
		return conn, &ok, nil
	}
	return nil, nil, errors.New("other server not reachable – " + strings.Join(errs, "; "))
}

type rejectedErr struct{ msg string }

func (e *rejectedErr) Error() string { return "rejected by the other server: " + e.msg }

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 80 {
		return s[i+2:]
	}
	return s
}

func (f *Federation) dialLoop(id string, stop chan struct{}) {
	defer f.wg.Done()
	backoff := 3 * time.Second
	for {
		select {
		case <-stop:
			return
		case <-f.stop:
			return
		default:
		}
		var link *FedLink
		f.srv.store.Read(func(s *State) {
			for _, l := range s.FedLinks {
				if l.ID == id {
					c := *l
					link = &c
				}
			}
		})
		if link == nil || !link.Enabled {
			return
		}
		f.mu.Lock()
		_, busy := f.conns[id]
		f.mu.Unlock()
		if !busy {
			conn, ok, err := f.dialAny(link)
			if err != nil {
				f.setStatus(id, err.Error())
			} else {
				if ok.Secret != "" { // first connection after an invite (Join failed half-way)
					f.srv.store.Update(func(s *State) {
						for _, l := range s.FedLinks {
							if l.ID == id {
								l.Secret, l.Invite = ok.Secret, ""
							}
						}
					})
					link.Secret = ok.Secret
				}
				backoff = 3 * time.Second
				f.session(conn, *link)
			}
		}
		select {
		case <-stop:
			return
		case <-f.stop:
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

// ---------- incoming connections ----------

func (f *Federation) Serve(l net.Listener) {
	f.srv.wg.Add(1)
	go func() {
		defer f.srv.wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				if f.srv.ctx.Err() != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go f.accept(conn)
		}
	}()
}

func (f *Federation) accept(raw net.Conn) {
	remote := raw.RemoteAddr().String()
	if !f.srv.store.Config().FedEnabled {
		raw.Close()
		return
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequireAnyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return f.srv.pki.ServerCert(), nil },
	}
	conn := tls.Server(raw, cfg)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	reject := func(msg string) {
		logf("Federation: connection from %s rejected: %s", remote, msg)
		writeFrame(conn, fError, []byte(msg))
		conn.Close()
	}
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return
	}
	var chain [][]byte
	for _, c := range conn.ConnectionState().PeerCertificates {
		chain = append(chain, c.Raw)
	}
	fp, err := peerCAFingerprint(chain)
	if err != nil {
		reject(err.Error())
		return
	}
	typ, payload, err := readFrame(conn)
	if err != nil || typ != fHello {
		conn.Close()
		return
	}
	var h helloMsg
	if json.Unmarshal(payload, &h) != nil || h.Proto != fedProto || h.UID == "" {
		reject("unknown protocol – update both servers to the same version")
		return
	}
	own := f.srv.store.Config()
	if h.UID == own.ServerUID {
		reject("a server cannot link to itself")
		return
	}
	var link *FedLink
	newSecret := ""
	errMsg := ""
	f.srv.store.Update(func(s *State) {
		if h.Invite != "" {
			now := time.Now()
			for i, inv := range s.FedInvites {
				if inv.Token == h.Invite && now.Before(inv.Expires) {
					s.FedInvites = append(s.FedInvites[:i], s.FedInvites[i+1:]...) // one-time
					newSecret = randomHex(24)
					keep := s.FedLinks[:0]
					for _, l := range s.FedLinks {
						if l.PeerUID != h.UID {
							keep = append(keep, l)
						}
					}
					link = &FedLink{ID: randomHex(6), PeerUID: h.UID, PeerName: h.Name, Secret: newSecret, PeerCAFP: fp,
						Enabled: true, Transit: true, Created: now}
					s.FedLinks = append(keep, link)
					return
				}
			}
			errMsg = "the invite code is unknown, expired or already used – create a new one"
			return
		}
		for _, l := range s.FedLinks {
			if l.PeerUID == h.UID && !l.Outgoing && l.Secret != "" && l.Secret == h.Secret {
				if !strings.EqualFold(l.PeerCAFP, fp) {
					errMsg = "certificate of the other server changed – link the servers again"
					return
				}
				if !l.Enabled {
					errMsg = "this link is switched off on " + own.ServerName
					return
				}
				l.PeerName = h.Name
				link = l
				return
			}
		}
		errMsg = "this server does not know you (link deleted?) – create a new invite"
	})
	if link == nil {
		reject(errMsg)
		return
	}
	lc := *link
	b, _ := json.Marshal(helloOK{UID: own.ServerUID, Name: own.ServerName, Secret: newSecret})
	if err := writeFrame(conn, fHelloOK, b); err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	if newSecret != "" {
		logf("Federation: %s joined with an invite (%s)", lc.PeerName, remote)
		f.Reconcile()
	}
	f.session(conn, lc)
}

// ---------- session (both directions) ----------

func (f *Federation) session(conn net.Conn, link FedLink) {
	c := &fedConn{f: f, link: link, conn: conn, out: make(chan fedItem, 4096), closed: make(chan struct{}),
		connected: time.Now(), remote: conn.RemoteAddr().String(), sentFiles: map[string]bool{}, recv: map[string]*os.File{}}
	f.mu.Lock()
	if old := f.conns[link.ID]; old != nil {
		old.Close()
	}
	f.conns[link.ID] = c
	f.status[link.ID] = ""
	f.mu.Unlock()
	logf("Federation: connected with %s (%s)", link.PeerName, c.remote)
	f.touch(link.ID)

	c.vt = newVideoTunnel(c)
	go c.writer()
	go c.offerFeedsLoop()
	// current positions so both sides see each other right away
	for _, raw := range f.srv.hub.LatestForFederation(link.ID) {
		if ev, err := ParseEvent(raw); err == nil {
			f.sendTo(c, raw, ev, nil, true)
		}
	}
	c.reader()
	c.Close()
	c.vt.close()
	f.srv.media.SetAuto(link.ID, nil)
	for _, fh := range c.recv {
		fh.Close()
		os.Remove(fh.Name())
	}
	f.mu.Lock()
	if f.conns[link.ID] == c {
		delete(f.conns, link.ID)
		f.status[link.ID] = "disconnected"
	}
	f.mu.Unlock()
	f.touch(link.ID)
	logf("Federation: disconnected from %s", link.PeerName)
}

func (f *Federation) touch(id string) {
	f.srv.store.Update(func(s *State) {
		for _, l := range s.FedLinks {
			if l.ID == id {
				l.LastSeen = time.Now()
			}
		}
	})
}

func (c *fedConn) writer() {
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	write := func(typ byte, p []byte) bool {
		c.conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if err := writeFrame(c.conn, typ, p); err != nil {
			c.Close()
			return false
		}
		c.tx.Add(1)
		return true
	}
	for {
		select {
		case <-c.closed:
			return
		case <-ping.C:
			if !write(fPing, nil) {
				return
			}
		case fr := <-c.vt.out: // video tunnel
			if !write(fr.typ, fr.payload) {
				return
			}
		case it := <-c.out:
			if it.fileHash != "" {
				if !c.streamFile(it.fileHash, write) {
					return
				}
				continue
			}
			if !write(it.typ, it.payload) {
				return
			}
		}
	}
}

func (c *fedConn) streamFile(hash string, write func(byte, []byte) bool) bool {
	pk := c.f.srv.packages.Get(hash)
	if pk == nil {
		return true
	}
	fh, err := c.f.srv.packages.Open(hash)
	if err != nil {
		return true
	}
	defer fh.Close()
	meta, _ := json.Marshal(fileMeta{Hash: pk.Hash, Name: pk.Name, Size: pk.Size, MIME: pk.MIME, Keywords: pk.Keywords, CreatorUID: pk.CreatorUID, User: pk.User, Tool: pk.Tool})
	if !write(fFileMeta, meta) {
		return false
	}
	buf := make([]byte, fedChunk)
	for {
		n, err := fh.Read(buf)
		if n > 0 && !write(fFileChunk, append([]byte(hash), buf[:n]...)) {
			return false
		}
		if err != nil {
			break
		}
	}
	return write(fFileEnd, []byte(hash))
}

func (c *fedConn) reader() {
	for {
		c.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		typ, p, err := readFrame(c.conn)
		if err != nil {
			return
		}
		c.rx.Add(1)
		switch typ {
		case fCoT:
			c.f.srv.hub.FromFederation(c, p)
		case fPing:
			c.enqueue(fedItem{typ: fPong})
		case fPong:
		case fFileMeta:
			var m fileMeta
			if json.Unmarshal(p, &m) != nil || !reHash.MatchString(m.Hash) || m.Size > fedFileLimit {
				continue
			}
			if c.f.srv.packages.Has(m.Hash) || c.recv[m.Hash] != nil {
				continue
			}
			tmp, err := os.CreateTemp(c.f.srv.packages.dir, "fed-*")
			if err != nil {
				continue
			}
			c.recv[m.Hash] = tmp
			c.recvMeta(m)
		case fFileChunk:
			if len(p) < 64 {
				continue
			}
			if fh := c.recv[string(p[:64])]; fh != nil {
				fh.Write(p[64:])
			}
		case fFileEnd:
			hash := string(p)
			fh := c.recv[hash]
			if fh == nil {
				continue
			}
			delete(c.recv, hash)
			c.finishFile(hash, fh)
		case fError:
			logf("Federation %s: %s", c.getLink().PeerName, string(p))
			return
		case fFeeds:
			c.receiveFeeds(p)
		case fStreamOpen, fStreamData, fStreamClose:
			c.vt.frame(typ, p)
		}
	}
}

var fedMetaMu sync.Mutex
var fedMeta = map[string]fileMeta{}

func (c *fedConn) recvMeta(m fileMeta) {
	fedMetaMu.Lock()
	fedMeta[m.Hash] = m
	fedMetaMu.Unlock()
}

func (c *fedConn) finishFile(hash string, fh *os.File) {
	defer os.Remove(fh.Name())
	fedMetaMu.Lock()
	m := fedMeta[hash]
	delete(fedMeta, hash)
	fedMetaMu.Unlock()
	if _, err := fh.Seek(0, 0); err != nil {
		fh.Close()
		return
	}
	pk, err := c.f.srv.packages.Save(fh, Package{Name: m.Name, MIME: m.MIME, Keywords: m.Keywords, CreatorUID: m.CreatorUID,
		User: m.User, Tool: m.Tool, Origin: "federation: " + c.getLink().PeerName}, hash)
	fh.Close()
	if err != nil {
		logf("Federation %s: file %s rejected: %v", c.getLink().PeerName, m.Name, err)
		return
	}
	logf("Federation: data package %s received from %s", pk.Name, c.getLink().PeerName)
}

// Broadcast sends an event to all federated servers that should get it.
// local = the event comes from a device of this server (otherwise it is in transit).
func (f *Federation) Broadcast(raw []byte, ev *Event, viaLink string, groups []string, local bool) {
	f.mu.Lock()
	conns := make([]*fedConn, 0, len(f.conns))
	for id, c := range f.conns {
		if id != viaLink {
			conns = append(conns, c)
		}
	}
	f.mu.Unlock()
	for _, c := range conns {
		f.sendTo(c, raw, ev, groups, local)
	}
}

func (f *Federation) sendTo(c *fedConn, raw []byte, ev *Event, groups []string, local bool) {
	l := c.getLink()
	if !l.Enabled || (!local && !l.Transit) {
		return
	}
	if len(l.Groups) > 0 && len(groups) > 0 && !intersects(groups, l.Groups) {
		return
	}
	if ev.HasFlowTag("WebTAK-Server-" + l.PeerUID) {
		return // the peer has seen it already
	}
	if fs := ev.Detail.Fileshare; fs != nil && fs.SHA256 != "" {
		hash := strings.ToLower(fs.SHA256)
		if pk := f.srv.packages.Get(hash); pk != nil && pk.Size <= fedFileLimit {
			c.mu.Lock()
			first := !c.sentFiles[hash]
			c.sentFiles[hash] = true
			c.mu.Unlock()
			if first {
				c.enqueue(fedItem{fileHash: hash})
			}
		}
	}
	c.enqueue(fedItem{typ: fCoT, payload: AddFlowTag(raw, f.srv.hub.fedTag())})
}

// ---------- status for the web UI ----------

func (f *Federation) Status() []map[string]any {
	links := f.links()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []map[string]any{}
	for _, l := range links {
		m := map[string]any{"id": l.ID, "peerName": l.PeerName, "peerUid": l.PeerUID, "outgoing": l.Outgoing,
			"addresses": l.Addresses, "enabled": l.Enabled, "groups": l.Groups, "transit": l.Transit,
			"created": l.Created, "lastSeen": l.LastSeen, "connected": false, "error": f.status[l.ID]}
		if c := f.conns[l.ID]; c != nil {
			m["connected"], m["since"], m["remote"], m["rx"], m["tx"] = true, c.connected, c.remote, c.rx.Load(), c.tx.Load()
			m["error"] = ""
		}
		out = append(out, m)
	}
	return out
}
