package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func startServer(t *testing.T, name string) *Server {
	t.Helper()
	dir := t.TempDir()
	srv, err := NewServer(dir, Ports{})
	if err != nil {
		t.Fatal(err)
	}
	srv.bindAddr = "127.0.0.1"
	srv.store.Update(func(s *State) {
		s.Config.ServerName = name
		s.Config.PublicHost = "127.0.0.1"
		s.Config.SetupDone = true
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

// ---------- test device ----------

type testClient struct {
	t    *testing.T
	conn net.Conn
	mu   sync.Mutex
	got  []*Event
	raws [][]byte
}

func dialTCP(t *testing.T, port int) *testClient {
	t.Helper()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	return newTestClient(t, c)
}

func newTestClient(t *testing.T, c net.Conn) *testClient {
	tc := &testClient{t: t, conn: c}
	t.Cleanup(func() { c.Close() })
	go func() {
		er := NewEventReader(c)
		for {
			raw, err := er.Next()
			if err != nil {
				return
			}
			ev, err := ParseEvent(raw)
			if err != nil {
				continue
			}
			tc.mu.Lock()
			tc.got = append(tc.got, ev)
			tc.raws = append(tc.raws, raw)
			tc.mu.Unlock()
		}
	}()
	return tc
}

func (tc *testClient) send(s string) {
	if _, err := tc.conn.Write([]byte(s)); err != nil {
		tc.t.Fatal(err)
	}
}

func sa(uid, callsign string) string {
	now := time.Now()
	return fmt.Sprintf(`<?xml version="1.0" standalone="yes"?><event version="2.0" uid="%s" type="a-f-G-U-C" how="m-g" time="%s" start="%s" stale="%s"><point lat="48.1" lon="11.5" hae="500" ce="10" le="10"/><detail><takv device="Test" platform="ATAK-CIV" os="34" version="5.2"/><contact callsign="%s" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Member"/></detail></event>`,
		uid, cotTime(now), cotTime(now), cotTime(now.Add(2*time.Minute)), callsign)
}

// waitFor waits until an event matching fn arrived and returns it.
func (tc *testClient) waitFor(what string, fn func(*Event) bool) (*Event, []byte) {
	tc.t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		tc.mu.Lock()
		for i, ev := range tc.got {
			if fn(ev) {
				raw := tc.raws[i]
				tc.mu.Unlock()
				return ev, raw
			}
		}
		tc.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	tc.t.Fatalf("timeout waiting for %s", what)
	return nil, nil
}

func (tc *testClient) count(fn func(*Event) bool) int {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	n := 0
	for _, ev := range tc.got {
		if fn(ev) {
			n++
		}
	}
	return n
}

func uidIs(uid string) func(*Event) bool { return func(e *Event) bool { return e.UID == uid } }

// ---------- tests ----------

func TestTCPRoutingPingAndLatestSA(t *testing.T) {
	srv := startServer(t, "A")
	a := dialTCP(t, srv.ports.TCP)
	b := dialTCP(t, srv.ports.TCP)
	a.send(sa("uid-a", "ALPHA"))
	b.waitFor("SA of A at B", uidIs("uid-a"))
	b.send(`<event version="2.0" uid="ping-b" type="t-x-c-t" how="h-g-i-g-o" time="2024-01-01T00:00:00Z" start="2024-01-01T00:00:00Z" stale="2030-01-01T00:00:00Z"><point lat="0" lon="0" hae="0" ce="0" le="0"/><detail/></event>`)
	b.waitFor("pong", func(e *Event) bool { return e.Type == "t-x-c-t-r" })
	if a.count(func(e *Event) bool { return e.Type == "t-x-c-t" }) != 0 {
		t.Fatal("ping must not be forwarded")
	}
	// a device connecting later gets the latest position right away
	c := dialTCP(t, srv.ports.TCP)
	c.send(sa("uid-c", "CHARLIE"))
	c.waitFor("latest SA of A at C", uidIs("uid-a"))
	// directed message only to CHARLIE
	b.send(`<event version="2.0" uid="msg1" type="b-t-f" how="h-g-i-g-o" time="2024-01-01T00:00:00Z" start="2024-01-01T00:00:00Z" stale="2030-01-01T00:00:00Z"><point lat="0" lon="0" hae="0" ce="0" le="0"/><detail><marti><dest callsign="CHARLIE"/></marti></detail></event>`)
	c.waitFor("directed message", uidIs("msg1"))
	time.Sleep(200 * time.Millisecond)
	if a.count(uidIs("msg1")) != 0 {
		t.Fatal("directed message reached the wrong device")
	}
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func TestEnrollmentAndSSL(t *testing.T) {
	srv := startServer(t, "A")
	if err := srv.CreateUser("bob", "secret-pass", false, nil); err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "bob"}}, key)
	csr := base64.StdEncoding.EncodeToString(csrDER)

	hc := httpClient()
	url := fmt.Sprintf("https://127.0.0.1:%d/Marti/api/tls/signClient/v2?clientUid=ANDROID-1&version=5.2", srv.ports.Enroll)
	req, _ := http.NewRequest("POST", url, strings.NewReader(csr))
	req.SetBasicAuth("bob", "wrong")
	if resp, err := hc.Do(req); err != nil || resp.StatusCode != 401 {
		t.Fatalf("wrong password must fail: %v %v", resp, err)
	}
	// with an enrollment token like in the ATAK QR code
	srv.store.Update(func(s *State) {
		s.Tokens = append(s.Tokens, &EnrollToken{Token: "tok123", Username: "bob", MaxUses: 1})
	})
	req, _ = http.NewRequest("POST", url, strings.NewReader(csr))
	req.SetBasicAuth("bob", "tok123")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("enrollment failed: %v %v", resp, err)
	}
	var out map[string]string
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	certDER, _ := base64.StdEncoding.DecodeString(out["signedCert"])
	caDER, _ := base64.StdEncoding.DecodeString(out["ca0"])
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	// token is used up
	req, _ = http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%d/Marti/api/tls/config", srv.ports.Enroll), nil)
	req.SetBasicAuth("bob", "tok123")
	if resp, _ := hc.Do(req); resp.StatusCode != 401 {
		t.Fatal("one-time token was accepted twice")
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	tlsCfg := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}}}
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.ports.SSL), tlsCfg)
	if err != nil {
		t.Fatalf("SSL connection: %v", err)
	}
	ssl := newTestClient(t, conn)
	tcp := dialTCP(t, srv.ports.TCP)
	ssl.send(sa("uid-bob", "BOB"))
	tcp.waitFor("SA from SSL client", uidIs("uid-bob"))
	tcp.send(sa("uid-anon", "ANON"))
	ssl.waitFor("SA from TCP client", uidIs("uid-anon"))

	// Marti API over HTTPS with the client certificate
	mc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	r2, err := mc.Get(fmt.Sprintf("https://127.0.0.1:%d/Marti/api/clientEndPoints", srv.ports.HTTPS))
	if err != nil || r2.StatusCode != 200 {
		t.Fatalf("clientEndPoints: %v %v", r2, err)
	}
	body, _ := io.ReadAll(r2.Body)
	if !strings.Contains(string(body), "BOB") {
		t.Fatalf("BOB missing in %s", body)
	}

	// deleting the user revokes the certificate and disconnects the device
	srv.DeleteUser("bob")
	if _, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.ports.SSL), tlsCfg); err == nil {
		// handshake may succeed on the client side; the server closes right after
		time.Sleep(100 * time.Millisecond)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(srv.hub.Clients()) > 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(srv.hub.Clients()); n != 1 {
		t.Fatalf("deleted user still connected (%d clients)", n)
	}
}

func TestConnectionPackage(t *testing.T) {
	srv := startServer(t, "A")
	srv.CreateUser("eve", "secret-pass", false, nil)
	zb, err := srv.ConnectionPackage("eve", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	for _, n := range []string{"MANIFEST/manifest.xml", "cert/server.pref", "cert/truststore.p12", "cert/eve.p12"} {
		if files[n] == nil {
			t.Fatalf("%s missing", n)
		}
	}
	if !strings.Contains(string(files["cert/server.pref"]), fmt.Sprintf("127.0.0.1:%d:ssl", srv.ports.SSL)) {
		t.Fatal("connect string missing")
	}
	cas, err := pkcs12.DecodeTrustStore(files["cert/truststore.p12"], "atakatak")
	if err != nil || len(cas) != 1 {
		t.Fatalf("truststore: %v", err)
	}
	key, cert, _, err := pkcs12.DecodeChain(files["cert/eve.p12"], "atakatak")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cas[0])
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.ports.SSL), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1",
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, conn)
	c.send(sa("uid-eve", "EVE"))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var ok bool
		srv.store.Read(func(s *State) { ok = s.EUDs["uid-eve"] != nil && s.EUDs["uid-eve"].Username == "eve" })
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("device of eve not registered")
}

func TestGroupsSeparateTeams(t *testing.T) {
	srv := startServer(t, "A")
	srv.CreateUser("red1", "secret-pass", false, []Membership{{"red", "IN"}, {"red", "OUT"}})
	srv.CreateUser("red2", "secret-pass", false, []Membership{{"red", "IN"}, {"red", "OUT"}})
	srv.CreateUser("blue1", "secret-pass", false, []Membership{{"blue", "IN"}, {"blue", "OUT"}})
	dial := func(user string) *testClient {
		p12, _, err := srv.pki.NewClientP12(user, "pw")
		if err != nil {
			t.Fatal(err)
		}
		key, cert, _, _ := pkcs12.DecodeChain(p12, "pw")
		conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.ports.SSL), &tls.Config{InsecureSkipVerify: true,
			Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}}})
		if err != nil {
			t.Fatal(err)
		}
		return newTestClient(t, conn)
	}
	r1, r2, b1 := dial("red1"), dial("red2"), dial("blue1")
	r1.send(sa("uid-r1", "RED1"))
	r2.waitFor("red sees red", uidIs("uid-r1"))
	time.Sleep(200 * time.Millisecond)
	if b1.count(uidIs("uid-r1")) != 0 {
		t.Fatal("blue must not see red")
	}
}

func TestDataPackageUpload(t *testing.T) {
	srv := startServer(t, "A")
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, _ := mw.CreateFormFile("assetfile", "plan.zip")
	fw.Write([]byte("zip-content"))
	mw.Close()
	url := fmt.Sprintf("http://127.0.0.1:%d/Marti/sync/missionupload?filename=plan.zip&creatorUid=x", srv.ports.HTTP)
	resp, err := http.Post(url, mw.FormDataContentType(), body)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("upload: %v %v", resp, err)
	}
	link, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(link), "/Marti/sync/content?hash=") {
		t.Fatalf("unexpected answer %s", link)
	}
	r2, err := http.Get(string(link))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r2.Body)
	if string(got) != "zip-content" {
		t.Fatalf("download: %q", got)
	}
	r3, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/Marti/sync/search?tool=public", srv.ports.HTTP))
	var res struct{ ResultCount int }
	json.NewDecoder(r3.Body).Decode(&res)
	if res.ResultCount != 1 {
		t.Fatalf("search: %d", res.ResultCount)
	}
}

func link(t *testing.T, a, b *Server) {
	t.Helper()
	code, err := a.fed.CreateInvite("test")
	if err != nil {
		t.Fatal(err)
	}
	// the invite lists the LAN addresses; in the test only 127.0.0.1 works
	if _, err := b.fed.Join(code, fmt.Sprintf("127.0.0.1:%d", a.ports.Fed)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fedConnected(a) && fedConnected(b) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("federation did not connect")
}

func fedConnected(s *Server) bool {
	st := s.fed.Status()
	if len(st) == 0 {
		return false
	}
	for _, l := range st {
		if l["connected"] != true {
			return false
		}
	}
	return true
}

func TestFederationBothDirectionsAndFiles(t *testing.T) {
	a := startServer(t, "Alpha")
	b := startServer(t, "Bravo")
	ca := dialTCP(t, a.ports.TCP)
	ca.send(sa("uid-a1", "A1")) // online before the link: must arrive with the initial sync
	time.Sleep(100 * time.Millisecond)
	link(t, a, b)
	cb := dialTCP(t, b.ports.TCP)
	cb.send(sa("uid-b1", "B1"))
	ca.waitFor("B1 at server A", uidIs("uid-b1"))
	cb.waitFor("A1 at server B", uidIs("uid-a1"))
	ca.send(sa("uid-a1", "A1"))
	_, raw := cb.waitFor("A1 live at server B", uidIs("uid-a1"))
	if !strings.Contains(string(raw), "WebTAK-Server-"+a.store.Config().ServerUID) {
		t.Fatal("flow tag missing")
	}

	// data package shared on A arrives on B with a download link to B
	pk, err := a.packages.Save(strings.NewReader("mission-data"), Package{Name: "mission.zip"}, "")
	if err != nil {
		t.Fatal(err)
	}
	ca.send(fmt.Sprintf(`<event version="2.0" uid="share1" type="b-f-t-r" how="h-e" time="2024-01-01T00:00:00Z" start="2024-01-01T00:00:00Z" stale="2030-01-01T00:00:00Z"><point lat="0" lon="0" hae="0" ce="0" le="0"/><detail><fileshare filename="mission.zip" senderUrl="https://10.9.9.9:8443/Marti/sync/content?hash=%s" sizeInBytes="12" sha256="%s" senderUid="uid-a1" senderCallsign="A1" name="mission"/><marti><dest callsign="B1"/></marti></detail></event>`, pk.Hash, pk.Hash))
	ev, _ := cb.waitFor("file share at B", uidIs("share1"))
	wantURL := fmt.Sprintf("http://127.0.0.1:%d/Marti/sync/content?hash=%s", b.ports.HTTP, pk.Hash)
	if ev.Detail.Fileshare.SenderURL != wantURL {
		t.Fatalf("senderUrl %s, want %s", ev.Detail.Fileshare.SenderURL, wantURL)
	}
	resp, err := http.Get(wantURL)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "mission-data" {
		t.Fatalf("file on B: %q", got)
	}

	// switching the link off stops the exchange, on again reconnects
	var id string
	b.store.Read(func(s *State) { id = s.FedLinks[0].ID })
	b.store.Update(func(s *State) { s.FedLinks[0].Enabled = false })
	b.fed.Reconcile()
	time.Sleep(300 * time.Millisecond)
	if fedConnected(a) {
		t.Fatal("still connected after switching off")
	}
	b.store.Update(func(s *State) {
		for _, l := range s.FedLinks {
			if l.ID == id {
				l.Enabled = true
			}
		}
	})
	b.fed.Reconcile()
	deadline := time.Now().Add(8 * time.Second)
	for !(fedConnected(a) && fedConnected(b)) {
		if time.Now().After(deadline) {
			t.Fatal("no reconnect")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestFederationChainNoLoops(t *testing.T) {
	a := startServer(t, "A")
	b := startServer(t, "B")
	c := startServer(t, "C")
	link(t, a, b)
	link(t, b, c)
	link(t, c, a) // a ring: loop protection must hold
	ca, cc := dialTCP(t, a.ports.TCP), dialTCP(t, c.ports.TCP)
	cb := dialTCP(t, b.ports.TCP)
	time.Sleep(100 * time.Millisecond)
	ca.send(sa("uid-ring", "RING"))
	cc.waitFor("A's device at C", uidIs("uid-ring"))
	cb.waitFor("A's device at B", uidIs("uid-ring"))
	time.Sleep(500 * time.Millisecond)
	if n := cc.count(uidIs("uid-ring")); n != 1 {
		t.Fatalf("C got the event %d times", n)
	}
	if n := ca.count(uidIs("uid-ring")); n != 0 {
		t.Fatalf("event looped back to the sender %d times", n)
	}
}

func TestFederationRejectsReusedInvite(t *testing.T) {
	a := startServer(t, "A")
	b := startServer(t, "B")
	c := startServer(t, "C")
	code, _ := a.fed.CreateInvite("")
	if _, err := b.fed.Join(code, fmt.Sprintf("127.0.0.1:%d", a.ports.Fed)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.fed.Join(code, fmt.Sprintf("127.0.0.1:%d", a.ports.Fed)); err == nil {
		t.Fatal("invite worked twice")
	}
}

func TestOTSAPI(t *testing.T) {
	srv := startServer(t, "A")
	srv.CreateUser("admin", "admin-pass", true, nil)
	base := fmt.Sprintf("https://127.0.0.1:%d", srv.ports.HTTPS)
	hc := httpClient()
	post := func(path, token string, body any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", base+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authentication-Token", token)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	code, out := post("/api/login?include_auth_token", "", map[string]string{"username": "admin", "password": "admin-pass"})
	if code != 200 {
		t.Fatalf("login %d %v", code, out)
	}
	tok := out["response"].(map[string]any)["user"].(map[string]any)["authentication_token"].(string)
	if code, out := post("/api/user/add", tok, map[string]any{"username": "max", "password": "max-pass-1", "confirm_password": "max-pass-1", "roles": []string{"user"}}); code != 200 {
		t.Fatalf("user/add %d %v", code, out)
	}
	if code, out := post("/api/groups", tok, map[string]any{"name": "team-red"}); code != 200 {
		t.Fatalf("groups %d %v", code, out)
	}
	req, _ := http.NewRequest("PUT", base+"/api/groups", strings.NewReader(`{"users":["max"],"group_name":"team-red","direction":"OUT"}`))
	req.Header.Set("Authentication-Token", tok)
	if resp, _ := hc.Do(req); resp.StatusCode != 200 {
		t.Fatal("add to group failed")
	}
	code, out = post("/api/atak_qr_string", tok, map[string]any{"username": "max"})
	if code != 200 || !strings.HasPrefix(out["qr_string"].(string), "tak://com.atakmap.app/enroll?host=") {
		t.Fatalf("qr %d %v", code, out)
	}
	req, _ = http.NewRequest("GET", base+"/api/users?username=max&per_page=50", nil)
	req.Header.Set("Authentication-Token", tok)
	resp, _ := hc.Do(req)
	var list struct {
		Results []struct {
			Username         string
			GroupMemberships []map[string]any `json:"group_memberships"`
		}
	}
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list.Results) != 1 || len(list.Results[0].GroupMemberships) != 3 {
		t.Fatalf("users: %+v", list)
	}
	// normal users get no admin API
	code, out = post("/api/login", "", map[string]string{"username": "max", "password": "max-pass-1"})
	utok := out["response"].(map[string]any)["user"].(map[string]any)["authentication_token"].(string)
	if code, _ := post("/api/user/delete", utok, map[string]string{"username": "admin"}); code != 403 {
		t.Fatalf("non-admin could delete: %d", code)
	}
	req, _ = http.NewRequest("GET", base+"/api/truststore", nil)
	req.Header.Set("Authentication-Token", tok)
	resp, _ = hc.Do(req)
	b, _ := io.ReadAll(resp.Body)
	if _, err := pkcs12.DecodeTrustStore(b, "atakatak"); err != nil {
		t.Fatal(err)
	}
}

func TestAdminSetupFlow(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(dir, Ports{TCP: -1, SSL: -1, Enroll: -1, Fed: -1})
	if err != nil {
		t.Fatal(err)
	}
	srv.bindAddr = "127.0.0.1"
	srv.Start()
	defer srv.Close()
	base := fmt.Sprintf("http://127.0.0.1:%d", srv.ports.HTTP)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	call := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.Header.Set("X-WTS", "1")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := call("GET", "/admin/api/dashboard", ""); code != 401 {
		t.Fatal("dashboard without login")
	}
	if code, b := call("POST", "/admin/api/setup", `{"password":"short"}`); code != 400 {
		t.Fatalf("short password accepted: %s", b)
	}
	if code, b := call("POST", "/admin/api/setup", `{"username":"admin","password":"long-enough","serverName":"Base"}`); code != 200 {
		t.Fatalf("setup: %s", b)
	}
	if code, _ := call("POST", "/admin/api/setup", `{"password":"another-pass"}`); code != 400 {
		t.Fatal("setup twice")
	}
	if code, b := call("GET", "/admin/api/dashboard", ""); code != 200 || !strings.Contains(b, `"serverName":"Base"`) {
		t.Fatalf("dashboard: %d %s", code, b)
	}
	if code, b := call("POST", "/admin/api/users", `{"username":"anna"}`); code != 200 || !strings.Contains(b, "password") {
		t.Fatalf("create user: %s", b)
	}
	if code, b := call("POST", "/admin/api/users/anna/enroll", `{}`); code != 200 || !strings.Contains(b, "atakQR") {
		t.Fatalf("enroll: %s", b)
	}
	if code, _ := call("GET", "/admin/api/users/anna/package", ""); code != 200 {
		t.Fatal("package download")
	}
	if code, b := call("GET", "/", ""); code != 200 || !strings.Contains(b, "<") {
		t.Fatal("UI not served")
	}
}
