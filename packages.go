package main

// Data packages (mission packages) and other files shared through the server, stored by SHA-256.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type PackageStore struct {
	dir   string
	store *Store
}

var reHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func OpenPackageStore(dir string, st *Store) (*PackageStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &PackageStore{dir: dir, store: st}, nil
}

func (p *PackageStore) path(hash string) string { return filepath.Join(p.dir, hash) }

func (p *PackageStore) Has(hash string) bool {
	hash = strings.ToLower(hash)
	if !reHash.MatchString(hash) {
		return false
	}
	ok := false
	p.store.Read(func(s *State) { ok = s.Packages[hash] != nil })
	return ok
}

func (p *PackageStore) Get(hash string) *Package {
	hash = strings.ToLower(hash)
	var out *Package
	p.store.Read(func(s *State) {
		if pk := s.Packages[hash]; pk != nil {
			c := *pk
			out = &c
		}
	})
	return out
}

func (p *PackageStore) Open(hash string) (*os.File, error) {
	hash = strings.ToLower(hash)
	if !reHash.MatchString(hash) {
		return nil, errors.New("invalid hash")
	}
	return os.Open(p.path(hash))
}

// Save stores a file. If wantHash is given and does not match, the upload is rejected.
func (p *PackageStore) Save(r io.Reader, meta Package, wantHash string) (*Package, error) {
	tmp, err := os.CreateTemp(p.dir, "upload-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	tmp.Close()
	if err != nil {
		return nil, err
	}
	hash := hex.EncodeToString(h.Sum(nil))
	if wantHash != "" && !strings.EqualFold(wantHash, hash) {
		return nil, errors.New("hash does not match the uploaded data")
	}
	if err := os.Rename(tmp.Name(), p.path(hash)); err != nil {
		return nil, err
	}
	meta.Hash, meta.Size = hash, n
	if meta.Name == "" {
		meta.Name = hash[:12]
	}
	meta.Name = filepath.Base(strings.ReplaceAll(meta.Name, "\\", "/"))
	if meta.MIME == "" {
		meta.MIME = mime.TypeByExtension(strings.ToLower(filepath.Ext(meta.Name)))
		if meta.MIME == "" {
			meta.MIME = "application/octet-stream"
		}
		if strings.HasSuffix(strings.ToLower(meta.Name), ".zip") {
			meta.MIME = "application/x-zip-compressed"
		}
	}
	if meta.Tool == "" {
		meta.Tool = "public"
	}
	if meta.Origin == "" {
		meta.Origin = "local"
	}
	meta.Submitted = time.Now().UTC()
	var out Package
	p.store.Update(func(s *State) {
		if old := s.Packages[hash]; old != nil {
			meta.PrimaryKey = old.PrimaryKey
		} else {
			meta.PrimaryKey = s.nextID()
		}
		s.Packages[hash] = &meta
		out = meta
	})
	return &out, nil
}

func (p *PackageStore) Delete(hash string) {
	hash = strings.ToLower(hash)
	if !reHash.MatchString(hash) {
		return
	}
	p.store.Update(func(s *State) { delete(s.Packages, hash) })
	os.Remove(p.path(hash))
}

func (p *PackageStore) List() []Package {
	var out []Package
	p.store.Read(func(s *State) {
		for _, pk := range s.Packages {
			out = append(out, *pk)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Submitted.After(out[j].Submitted) })
	return out
}

// Marti JSON of a resource (TAK Server format, used by ATAK/WinTAK data package lists)
func (pk *Package) Marti() map[string]any {
	kw := pk.Keywords
	if kw == nil {
		kw = []string{}
	}
	return map[string]any{
		"UID": pk.Hash, "Name": pk.Name, "Hash": pk.Hash, "PrimaryKey": pk.PrimaryKey,
		"SubmissionDateTime": pk.Submitted.Format("2006-01-02T15:04:05.000Z"), "SubmissionUser": pk.User,
		"CreatorUid": pk.CreatorUID, "Keywords": kw, "MIMEType": pk.MIME, "Size": pk.Size, "Tool": pk.Tool,
		"Expiration": -1,
	}
}
