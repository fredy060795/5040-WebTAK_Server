package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type identity struct {
	User  string
	Admin bool
	Via   string // cert, basic, token, session, anon
}

type ctxKey int

func (s *Server) serveHTTP(l net.Listener, mode string) {
	h := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.dispatch(w, r, mode) }))
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 20 * time.Second, ErrorLog: nil}
	if mode != "http" {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.pki.WebCertificate}
		if mode == "https" {
			// devices identify with their client certificate, browsers without
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
			cfg.ClientCAs = s.pki.CAPool
		}
		l = tls.NewListener(l, cfg)
	}
	s.https = append(s.https, srv)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		srv.Serve(l)
	}()
}

func isLoopback(r *http.Request) bool {
	ip := net.ParseIP(hostOnly(r.RemoteAddr))
	return ip != nil && ip.IsLoopback()
}

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, mode string) {
	defer func() {
		if e := recover(); e != nil {
			logf("PANIC %s %s: %v", r.Method, r.URL.Path, e)
			http.Error(w, "internal error", 500)
		}
	}()
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/Marti/"):
		s.handleMarti(w, r, mode)
	case strings.HasPrefix(p, "/api/"):
		s.handleOTSAPI(w, r)
	case strings.HasPrefix(p, "/admin/api/"):
		if mode == "http" && !isLoopback(r) {
			jsonErr(w, 403, "Please use the HTTPS address for the web interface.")
			return
		}
		s.handleAdmin(w, r)
	default:
		// web UI: over HTTPS, or over plain HTTP only from this computer
		if mode == "http" && !isLoopback(r) {
			host := hostOnly(r.Host)
			http.Redirect(w, r, "https://"+joinHostPort(host, s.ports.HTTPS)+r.URL.RequestURI(), http.StatusFound)
			return
		}
		s.serveUI(w, r)
	}
}

// who identifies the caller: client certificate, session cookie, API token or basic auth.
func (s *Server) who(r *http.Request) *identity {
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		if name, err := s.certUser(r.TLS.VerifiedChains[0][0]); err == nil {
			return s.ident(name, "cert")
		}
	}
	if c, err := r.Cookie("wts_session"); err == nil {
		if name := s.sessions.get(c.Value); name != "" {
			if id := s.ident(name, "session"); id != nil {
				return id
			}
		}
	}
	if tok := r.Header.Get("Authentication-Token"); tok != "" {
		var name string
		s.store.Read(func(st *State) {
			for _, u := range st.Users {
				if u.APIToken != "" && u.APIToken == tok && u.Active {
					name = u.Username
				}
			}
		})
		if name != "" {
			return s.ident(name, "token")
		}
	}
	if user, pw, ok := r.BasicAuth(); ok {
		if s.checkLogin(user, pw, true) {
			return s.ident(user, "basic")
		}
	}
	return nil
}

func (s *Server) ident(name, via string) *identity {
	var id *identity
	s.store.Read(func(st *State) {
		if u := findUser(st, name); u != nil && u.Active {
			id = &identity{User: u.Username, Admin: u.Admin, Via: via}
		}
	})
	return id
}

// checkLogin: password, or (allowToken) an enrollment token from a QR code.
func (s *Server) checkLogin(user, pw string, allowToken bool) bool {
	var hash string
	active := false
	s.store.Read(func(st *State) {
		if u := findUser(st, user); u != nil {
			hash, active = u.PassHash, u.Active
		}
	})
	if !active {
		return false
	}
	if checkPassword(hash, pw) {
		return true
	}
	if !allowToken {
		return false
	}
	ok := false
	s.store.Update(func(st *State) {
		now := time.Now()
		keep := st.Tokens[:0]
		for _, t := range st.Tokens {
			expired := (!t.Expires.IsZero() && now.After(t.Expires)) || (t.MaxUses > 0 && t.Uses >= t.MaxUses)
			if !expired && !ok && t.Username == user && t.Token == pw {
				t.Uses++
				ok = true
			}
			if !expired {
				keep = append(keep, t)
			}
		}
		st.Tokens = keep
	})
	return ok
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg, "success": false})
}

func readJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	return json.Unmarshal(b, v)
}

// clientHost: the server address as the caller used it (without port)
func clientHost(r *http.Request) string {
	if h := hostOnly(r.Host); h != "" {
		return h
	}
	return hostOnly(r.Context().Value(http.LocalAddrContextKey).(net.Addr).String())
}
