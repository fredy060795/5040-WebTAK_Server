package main

// Own certificate authority: created on first start, signs the server certificate (renewed
// automatically when the IP address changes) and the client certificates of the devices.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type PKI struct {
	dir    string
	CACert *x509.Certificate
	CAKey  crypto.Signer
	CAPool *x509.CertPool

	mu         sync.RWMutex
	serverCert *tls.Certificate
	serverSANs []string
	webCert    *tls.Certificate // optional own certificate for the HTTPS ports (Let's Encrypt etc.)
	webMod     time.Time
	extraHosts func() []string
}

func newSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600)
}

func readPEM(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM data in " + path)
	}
	return blk.Bytes, nil
}

func LoadPKI(dir, serverName string, extraHosts func() []string) (*PKI, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := &PKI{dir: dir, extraHosts: extraHosts}
	caPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		logf("Creating certificate authority (first start) …")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		name := strings.TrimSpace(serverName)
		if name == "" {
			name = "WebTAK Server"
		}
		tpl := &x509.Certificate{
			SerialNumber:          newSerial(),
			Subject:               pkix.Name{CommonName: name + " CA " + randomHex(3), Organization: []string{"WebTAK"}, OrganizationalUnit: []string{"TAK"}},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().AddDate(20, 0, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		if err := writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
			return nil, err
		}
		if err := writePEM(caPath, "CERTIFICATE", der); err != nil {
			return nil, err
		}
	}
	der, err := readPEM(caPath)
	if err != nil {
		return nil, err
	}
	if p.CACert, err = x509.ParseCertificate(der); err != nil {
		return nil, err
	}
	kder, err := readPEM(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(kder)
	if err != nil {
		return nil, err
	}
	p.CAKey = key
	p.CAPool = x509.NewCertPool()
	p.CAPool.AddCert(p.CACert)
	if err := p.ensureServerCert(); err != nil {
		return nil, err
	}
	return p, nil
}

// SHA-256 fingerprint of the CA (used to pin federation peers)
func (p *PKI) CAFingerprint() string {
	s := sha256.Sum256(p.CACert.Raw)
	return hex.EncodeToString(s[:])
}

func certFingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

func (p *PKI) wantedSANs() []string {
	set := map[string]bool{"localhost": true, "127.0.0.1": true}
	if h := hostname(); h != "" {
		set[h] = true
	}
	for _, ip := range localIPs() {
		set[ip] = true
	}
	if p.extraHosts != nil {
		for _, h := range p.extraHosts() {
			if h = strings.TrimSpace(hostOnly(h)); h != "" {
				set[h] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// ensureServerCert (re)issues the server certificate when an address is missing in it.
func (p *PKI) ensureServerCert() error {
	want := p.wantedSANs()
	p.mu.RLock()
	have := p.serverSANs
	p.mu.RUnlock()
	if have != nil && strings.Join(have, ",") == strings.Join(want, ",") {
		return nil
	}
	certPath, keyPath := filepath.Join(p.dir, "server.pem"), filepath.Join(p.dir, "server-key.pem")
	if have == nil { // first call: reuse the certificate on disk if it still fits
		if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
			leaf, err := x509.ParseCertificate(c.Certificate[0])
			if err == nil && time.Until(leaf.NotAfter) > 30*24*time.Hour && leaf.CheckSignatureFrom(p.CACert) == nil {
				names := append([]string{}, leaf.DNSNames...)
				for _, ip := range leaf.IPAddresses {
					names = append(names, ip.String())
				}
				sort.Strings(names)
				if strings.Join(names, ",") == strings.Join(want, ",") {
					c.Leaf = leaf
					p.mu.Lock()
					p.serverCert, p.serverSANs = &c, want
					p.mu.Unlock()
					return nil
				}
			}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: firstNonIP(want), Organization: []string{"WebTAK"}, OrganizationalUnit: []string{"TAK"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		// ClientAuth too: the certificate also identifies this server towards federation peers
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, h := range want {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.CACert, &key.PublicKey, p.CAKey)
	if err != nil {
		return err
	}
	writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	os.WriteFile(certPath, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.CACert.Raw})...), 0o600)
	leaf, _ := x509.ParseCertificate(der)
	c := &tls.Certificate{Certificate: [][]byte{der, p.CACert.Raw}, PrivateKey: key, Leaf: leaf}
	p.mu.Lock()
	p.serverCert, p.serverSANs = c, want
	p.mu.Unlock()
	logf("Server certificate issued for: %s", strings.Join(want, ", "))
	return nil
}

func firstNonIP(names []string) string {
	for _, n := range names {
		if net.ParseIP(n) == nil && n != "localhost" {
			return n
		}
	}
	return "webtak-server"
}

func (p *PKI) ServerCert() *tls.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.serverCert
}

// SetWebCert loads an own certificate for the web/API ports; reloaded when the files change.
func (p *PKI) SetWebCert(certFile, keyFile string) error {
	if certFile == "" || keyFile == "" {
		p.mu.Lock()
		p.webCert = nil
		p.mu.Unlock()
		return nil
	}
	st, err := os.Stat(certFile)
	if err != nil {
		return err
	}
	p.mu.RLock()
	same := p.webCert != nil && st.ModTime().Equal(p.webMod)
	p.mu.RUnlock()
	if same {
		return nil
	}
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.webCert, p.webMod = &c, st.ModTime()
	p.mu.Unlock()
	logf("Own web certificate loaded: %s", certFile)
	return nil
}

// Certificate for the HTTPS ports: own certificate (if set) for browsers using a DNS name,
// otherwise the server certificate of the own CA (which ATAK trusts through the truststore).
func (p *PKI) WebCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.webCert != nil && hello.ServerName != "" && net.ParseIP(hello.ServerName) == nil {
		return p.webCert, nil
	}
	return p.serverCert, nil
}

// ---------- client certificates ----------

func (p *PKI) signClient(pub crypto.PublicKey, username string, days int) (*x509.Certificate, error) {
	tpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: username, Organization: []string{"WebTAK"}, OrganizationalUnit: []string{"TAK"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.CACert, pub, p.CAKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// NewClientP12 creates key + certificate for a user as PKCS#12 (for connection data packages).
func (p *PKI) NewClientP12(username, password string) ([]byte, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	cert, err := p.signClient(&key.PublicKey, username, 3650)
	if err != nil {
		return nil, nil, err
	}
	b, err := pkcs12.Legacy.Encode(key, cert, []*x509.Certificate{p.CACert}, password)
	return b, cert, err
}

// SignCSR signs a certificate request sent by ATAK/iTAK/WinTAK during enrollment.
// The common name is always set to the authenticated user.
func (p *PKI) SignCSR(body []byte, username string) (*x509.Certificate, error) {
	s := strings.TrimSpace(string(body))
	var der []byte
	if blk, _ := pem.Decode([]byte(s)); blk != nil {
		der = blk.Bytes
	} else {
		s = strings.NewReplacer("-----BEGIN CERTIFICATE REQUEST-----", "", "-----END CERTIFICATE REQUEST-----", "",
			"-----BEGIN NEW CERTIFICATE REQUEST-----", "", "-----END NEW CERTIFICATE REQUEST-----", "", "\n", "", "\r", "", " ", "").Replace(s)
		var err error
		if der, err = base64.StdEncoding.DecodeString(s); err != nil {
			return nil, fmt.Errorf("certificate request is not readable: %v", err)
		}
	}
	pub, err := csrPublicKey(der)
	if err != nil {
		return nil, err
	}
	return p.signClient(pub, username, 3650)
}

// csrPublicKey returns the verified public key of a certificate request. The subject is not needed (the
// common name is always the user) – and some clients encode it in ways Go's strict parser refuses, e.g.
// node-forge puts "alpha_10" into a PrintableString, where "_" is not allowed. OTS accepts those, so do we.
func csrPublicKey(der []byte) (crypto.PublicKey, error) {
	if csr, err := x509.ParseCertificateRequest(der); err == nil {
		if err := csr.CheckSignature(); err != nil {
			return nil, err
		}
		return csr.PublicKey, nil
	}
	var raw struct {
		Info struct {
			Raw     asn1.RawContent
			Version int
			Subject asn1.RawValue
			PKInfo  asn1.RawValue
			Attrs   asn1.RawValue `asn1:"optional,tag:0"`
		}
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("certificate request is not readable: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(raw.Info.PKInfo.FullBytes)
	if err != nil {
		return nil, err
	}
	algs := map[string]x509.SignatureAlgorithm{
		"1.2.840.113549.1.1.5": x509.SHA1WithRSA, "1.2.840.113549.1.1.11": x509.SHA256WithRSA,
		"1.2.840.113549.1.1.12": x509.SHA384WithRSA, "1.2.840.113549.1.1.13": x509.SHA512WithRSA,
		"1.2.840.10045.4.3.2": x509.ECDSAWithSHA256, "1.2.840.10045.4.3.3": x509.ECDSAWithSHA384, "1.2.840.10045.4.3.4": x509.ECDSAWithSHA512,
	}
	alg, ok := algs[raw.SigAlg.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("certificate request: unsupported signature %s", raw.SigAlg.Algorithm)
	}
	if err := (&x509.Certificate{PublicKey: pub}).CheckSignature(alg, raw.Info.Raw, raw.Sig.RightAlign()); err != nil {
		return nil, fmt.Errorf("certificate request signature: %v", err)
	}
	return pub, nil
}

func (p *PKI) TrustStoreP12(password string) ([]byte, error) {
	return pkcs12.Legacy.EncodeTrustStore([]*x509.Certificate{p.CACert}, password)
}

func (p *PKI) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.CACert.Raw})
}

func serialHex(c *x509.Certificate) string { return c.SerialNumber.Text(16) }
