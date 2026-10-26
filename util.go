package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const AnonGroup = "__ANON__"

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Easy to type: no 0/O, 1/l/I
func randomPassword(n int) string {
	const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

// ---------- log with ring buffer (shown in the web UI) ----------

type logRing struct {
	mu    sync.Mutex
	lines []string
}

var logs = &logRing{}

func logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	logs.mu.Lock()
	logs.lines = append(logs.lines, time.Now().Format("2006-01-02 15:04:05")+"  "+msg)
	if len(logs.lines) > 1000 {
		logs.lines = logs.lines[len(logs.lines)-1000:]
	}
	logs.mu.Unlock()
}

func recentLogs() []string {
	logs.mu.Lock()
	defer logs.mu.Unlock()
	return append([]string(nil), logs.lines...)
}

// ---------- passwords (PBKDF2-SHA256, standard library only) ----------

const pbkdfIter = 120000

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdfIter, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// Devices log in often (enrollment, data packages); remembering successful checks keeps a
// Raspberry Pi from spending a second of CPU on every request.
var pwCache sync.Map // sha256(hash|pw) -> time

func checkPassword(hash, pw string) bool {
	if hash == "" || pw == "" {
		return false
	}
	ck := sha256.Sum256([]byte(hash + "\x00" + pw))
	if t, ok := pwCache.Load(ck); ok && time.Since(t.(time.Time)) < 10*time.Minute {
		return true
	}
	p := strings.Split(hash, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, _ := strconv.Atoi(p[1])
	salt, err1 := base64.RawStdEncoding.DecodeString(p[2])
	want, err2 := base64.RawStdEncoding.DecodeString(p[3])
	if err1 != nil || err2 != nil || iter <= 0 {
		return false
	}
	got, _ := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false
	}
	pwCache.Store(ck, time.Now())
	return true
}

func validUsername(u string) bool {
	if len(u) < 1 || len(u) > 64 {
		return false
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '@') {
			return false
		}
	}
	return true
}

// ---------- network addresses ----------

// Local IPv4 addresses (LAN, ZeroTier, Tailscale …) without loopback, sorted: private LAN first.
func localIPs() []string {
	var out []string
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ipn.IP.String())
		}
	}
	rank := func(ip string) int {
		switch {
		case strings.HasPrefix(ip, "192.168."):
			return 0
		case strings.HasPrefix(ip, "10."):
			return 1
		case strings.HasPrefix(ip, "172."):
			return 2
		}
		return 3
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
