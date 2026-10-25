package main

// Video between federated servers.
//
// Each server tells its peers which video feeds it has (fFeeds). The peer creates matching streams
// "fed-<server>/<path>" in its own video server, pulled on demand. The video itself travels through a
// tunnel inside the federation connection (fStreamOpen/Data/Close carrying RTSP over TCP), so it works
// in both directions even when only one server can reach the other – and only while someone watches.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

type fedFeed struct {
	Path       string `json:"path"` // path on the sending server
	Alias      string `json:"alias"`
	Origin     string `json:"origin"` // server UID where the video comes from
	OriginName string `json:"originName"`
	OPath      string `json:"opath"` // path on the origin server
	Hops       int    `json:"hops"`
}

const maxVideoHops = 4

type tunnelFrame struct {
	typ     byte
	payload []byte
}

type tunnelStream struct {
	id   uint32
	conn net.Conn
	in   chan []byte
	once sync.Once
}

type videoTunnel struct {
	c       *fedConn
	ln      net.Listener
	port    int
	mu      sync.Mutex
	streams map[uint32]*tunnelStream
	next    uint32
	out     chan tunnelFrame
	closed  chan struct{}
	once    sync.Once
}

func newVideoTunnel(c *fedConn) *videoTunnel {
	vt := &videoTunnel{c: c, streams: map[uint32]*tunnelStream{}, out: make(chan tunnelFrame, 256), closed: make(chan struct{})}
	// ids: the side that dialed uses odd numbers, the other even ones – no collisions
	vt.next = 2
	if c.link.Outgoing {
		vt.next = 1
	}
	if ln, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		vt.ln, vt.port = ln, ln.Addr().(*net.TCPAddr).Port
		go vt.accept()
	}
	return vt
}

func (vt *videoTunnel) close() {
	vt.once.Do(func() {
		close(vt.closed)
		if vt.ln != nil {
			vt.ln.Close()
		}
		vt.mu.Lock()
		for _, st := range vt.streams {
			st.conn.Close()
		}
		vt.streams = map[uint32]*tunnelStream{}
		vt.mu.Unlock()
	})
}

func idBytes(id uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, id)
	return b
}

// send queues a frame; video waits for the connection instead of being dropped (back pressure).
func (vt *videoTunnel) send(typ byte, payload []byte) bool {
	select {
	case vt.out <- tunnelFrame{typ, payload}:
		return true
	case <-vt.closed:
		return false
	case <-time.After(20 * time.Second):
		return false
	}
}

// accept: our video server connects here to pull a stream from the peer.
func (vt *videoTunnel) accept() {
	for {
		conn, err := vt.ln.Accept()
		if err != nil {
			return
		}
		vt.mu.Lock()
		id := vt.next
		vt.next += 2
		st := vt.add(id, conn)
		vt.mu.Unlock()
		if !vt.send(fStreamOpen, idBytes(id)) {
			vt.drop(st, false)
			continue
		}
		vt.pump(st)
	}
}

func (vt *videoTunnel) add(id uint32, conn net.Conn) *tunnelStream {
	st := &tunnelStream{id: id, conn: conn, in: make(chan []byte, 512)}
	vt.streams[id] = st
	go func() { // peer -> local
		for {
			select {
			case b := <-st.in:
				conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
				if _, err := conn.Write(b); err != nil {
					vt.drop(st, true)
					return
				}
			case <-vt.closed:
				return
			}
		}
	}()
	return st
}

// pump: local -> peer
func (vt *videoTunnel) pump(st *tunnelStream) {
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := st.conn.Read(buf)
			if n > 0 {
				if !vt.send(fStreamData, append(idBytes(st.id), buf[:n]...)) {
					vt.drop(st, false)
					return
				}
			}
			if err != nil {
				vt.drop(st, true)
				return
			}
		}
	}()
}

func (vt *videoTunnel) drop(st *tunnelStream, notify bool) {
	st.once.Do(func() {
		st.conn.Close()
		vt.mu.Lock()
		delete(vt.streams, st.id)
		vt.mu.Unlock()
		if notify {
			select {
			case vt.out <- tunnelFrame{fStreamClose, idBytes(st.id)}:
			default:
			}
		}
	})
}

func (vt *videoTunnel) frame(typ byte, p []byte) {
	if len(p) < 4 {
		return
	}
	id := binary.BigEndian.Uint32(p[:4])
	vt.mu.Lock()
	st := vt.streams[id]
	vt.mu.Unlock()
	switch typ {
	case fStreamOpen:
		srv := vt.c.f.srv
		_, _, running := srv.media.Status()
		if !running || srv.ports.RTSP <= 0 || !srv.store.Config().VideoFedShare {
			vt.send(fStreamClose, idBytes(id))
			return
		}
		host := srv.bindAddr
		if host == "" {
			host = "127.0.0.1"
		}
		conn, err := net.DialTimeout("tcp", joinHostPort(host, srv.ports.RTSP), 5*time.Second)
		if err != nil {
			vt.send(fStreamClose, idBytes(id))
			return
		}
		vt.mu.Lock()
		st = vt.add(id, conn)
		vt.mu.Unlock()
		vt.pump(st)
	case fStreamData:
		if st == nil {
			return
		}
		select {
		case st.in <- p[4:]:
		default:
			vt.drop(st, true) // the local side does not keep up
		}
	case fStreamClose:
		if st != nil {
			vt.drop(st, false)
		}
	}
}

// ---------- feed lists ----------

// exportFeeds: the feeds offered to one federation link.
func (m *Media) exportFeeds(linkID string, transit bool) []fedFeed {
	cfg := m.srv.store.Config()
	out := []fedFeed{}
	for _, f := range m.Feeds() {
		switch f.Kind {
		case "pushed", "pulled":
			if f.Kind == "pushed" && !f.Live {
				continue
			}
			out = append(out, fedFeed{Path: f.Path, Alias: f.Alias, Origin: cfg.ServerUID, OriginName: cfg.ServerName, OPath: f.Path})
		}
	}
	if transit {
		for _, a := range m.autoPaths() {
			if a.Owner == linkID || a.Hops+1 >= maxVideoHops {
				continue
			}
			out = append(out, fedFeed{Path: a.Name, Alias: a.Alias, Origin: a.Origin, OriginName: a.OriginName, OPath: a.OPath, Hops: a.Hops})
		}
	}
	return out
}

func (c *fedConn) offerFeedsLoop() {
	var last string
	lastSent := time.Time{}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		srv := c.f.srv
		feeds := []fedFeed{}
		_, _, running := srv.media.Status()
		if srv.store.Config().VideoFedShare && running {
			l := c.getLink()
			feeds = srv.media.exportFeeds(l.ID, l.Transit)
		}
		b, _ := json.Marshal(feeds)
		if string(b) != last || time.Since(lastSent) > time.Minute {
			c.enqueue(fedItem{typ: fFeeds, payload: b})
			last, lastSent = string(b), time.Now()
		}
		select {
		case <-c.closed:
			return
		case <-t.C:
		}
	}
}

func (c *fedConn) receiveFeeds(p []byte) {
	var feeds []fedFeed
	if json.Unmarshal(p, &feeds) != nil {
		return
	}
	srv := c.f.srv
	own := srv.store.Config()
	l := c.getLink()
	var paths []autoPath
	if own.VideoFedShare && c.vt.port > 0 {
		for _, e := range feeds {
			if e.Origin == own.ServerUID || e.Hops+1 > maxVideoHops || !validPath(slugPath(e.Path)) {
				continue
			}
			name := "fed-" + slugName(e.OriginName) + "/" + slugPath(e.OPath)
			if strings.HasPrefix(e.OPath, "fed-") || strings.HasPrefix(e.OPath, "ots-") {
				name = slugPath(e.OPath) // already a linked stream on the origin
			}
			if srv.media.autoTaken(name, l.ID, e.Hops+1) {
				continue
			}
			src := fmt.Sprintf("rtsp://%s@127.0.0.1:%d/%s", url.UserPassword("fed-"+own.ServerUID, l.Secret).String(), c.vt.port, e.Path)
			paths = append(paths, autoPath{Name: name, Source: src, Alias: e.Alias,
				Origin: e.Origin, OriginName: e.OriginName, OPath: e.OPath, Hops: e.Hops + 1, Owner: l.ID, TCP: true})
		}
	}
	srv.media.SetAuto(l.ID, paths)
}
