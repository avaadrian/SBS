// Package scanner is a signature-based file scanner: exact SHA-256 hashes plus
// YARA-style string signatures ("any", "all" or "N of" the strings).
//
//	hashes:
//	  - sha256: 275a021b...
//	    name: EICAR-Test-File
//	signatures:
//	  - name: Linux.CoinMiner.XMRig
//	    severity: high
//	    strings: ["stratum+tcp://", "hex:786d726967"]
//	    condition: all
package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// DefaultMaxSize is the largest file the scanner reads.
const DefaultMaxSize = 32 << 20

// HashSig matches a file by exact SHA-256.
type HashSig struct {
	SHA256   string `yaml:"sha256"`
	Name     string `yaml:"name"`
	Severity string `yaml:"severity"`
}

// StringSig matches when the condition over its strings holds.
type StringSig struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Strings     []string `yaml:"strings"`
	Condition   string   `yaml:"condition"` // any | all | <N>
	NoCase      bool     `yaml:"nocase"`

	pats [][]byte
	need int
}

// SigFile is the on-disk signature format.
type SigFile struct {
	Hashes     []HashSig   `yaml:"hashes"`
	Signatures []StringSig `yaml:"signatures"`
}

// Match is a positive scan result.
type Match struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
	Severity  string `json:"severity"`
	Kind      string `json:"kind"` // hash | strings
}

// Scanner holds compiled signatures. It is safe for concurrent use.
type Scanner struct {
	hashes  map[string]HashSig
	sigs    []StringSig
	MaxSize int64

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	size, mtime int64
	sha         string
	matches     []Match
}

// New returns an empty scanner.
func New() *Scanner {
	return &Scanner{hashes: map[string]HashSig{}, MaxSize: DefaultMaxSize, cache: map[string]cacheEntry{}}
}

// Add parses and compiles a signature file.
func (s *Scanner) Add(data []byte, name string) error {
	var sf SigFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	for _, h := range sf.Hashes {
		h.SHA256 = strings.ToLower(strings.TrimSpace(h.SHA256))
		if len(h.SHA256) != 64 {
			return fmt.Errorf("%s: hash %q for %s is not a sha256", name, h.SHA256, h.Name)
		}
		if h.Severity == "" {
			h.Severity = "high"
		}
		s.hashes[h.SHA256] = h
	}
	for _, sg := range sf.Signatures {
		if sg.Name == "" || len(sg.Strings) == 0 {
			return fmt.Errorf("%s: signature needs a name and strings", name)
		}
		if sg.Severity == "" {
			sg.Severity = "high"
		}
		for _, str := range sg.Strings {
			var p []byte
			if hx, ok := strings.CutPrefix(str, "hex:"); ok {
				b, err := hex.DecodeString(strings.ReplaceAll(hx, " ", ""))
				if err != nil {
					return fmt.Errorf("%s: %s: %w", name, sg.Name, err)
				}
				p = b
			} else {
				p = []byte(str)
			}
			if sg.NoCase {
				p = bytes.ToLower(p)
			}
			sg.pats = append(sg.pats, p)
		}
		switch sg.Condition {
		case "", "any":
			sg.need = 1
		case "all":
			sg.need = len(sg.pats)
		default:
			n, err := strconv.Atoi(sg.Condition)
			if err != nil || n < 1 || n > len(sg.pats) {
				return fmt.Errorf("%s: %s: bad condition %q", name, sg.Name, sg.Condition)
			}
			sg.need = n
		}
		s.sigs = append(s.sigs, sg)
	}
	return nil
}

// AddFS loads every YAML file in fsys.
func (s *Scanner) AddFS(fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (filepath.Ext(p) != ".yaml" && filepath.Ext(p) != ".yml") {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		return s.Add(data, p)
	})
}

// AddPath loads a signature file or a directory of them.
func (s *Scanner) AddPath(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return s.AddFS(os.DirFS(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return s.Add(data, path)
}

// Count returns the number of hash and string signatures loaded.
func (s *Scanner) Count() (hashes, strs int) { return len(s.hashes), len(s.sigs) }

// ScanBytes checks a buffer against all signatures.
func (s *Scanner) ScanBytes(data []byte) (sha string, out []Match) {
	sum := sha256.Sum256(data)
	sha = hex.EncodeToString(sum[:])
	if h, ok := s.hashes[sha]; ok {
		out = append(out, Match{SHA256: sha, Signature: h.Name, Severity: h.Severity, Kind: "hash"})
	}
	var lower []byte
	for i := range s.sigs {
		sg := &s.sigs[i]
		buf := data
		if sg.NoCase {
			if lower == nil {
				lower = bytes.ToLower(data)
			}
			buf = lower
		}
		hits := 0
		for _, p := range sg.pats {
			if bytes.Contains(buf, p) {
				hits++
				if hits >= sg.need {
					break
				}
			}
		}
		if hits >= sg.need {
			out = append(out, Match{SHA256: sha, Signature: sg.Name, Severity: sg.Severity, Kind: "strings"})
		}
	}
	return sha, out
}

// ScanFile scans a regular file. Results are cached by path, size and mtime.
// Files larger than MaxSize are skipped (sha is empty).
func (s *Scanner) ScanFile(path string) (sha string, out []Match, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > s.MaxSize {
		return "", nil, nil
	}
	mt := st.ModTime().UnixNano()
	s.mu.Lock()
	if c, ok := s.cache[path]; ok && c.size == st.Size() && c.mtime == mt {
		s.mu.Unlock()
		return c.sha, c.matches, nil
	}
	s.mu.Unlock()

	data, err := io.ReadAll(io.LimitReader(f, s.MaxSize))
	if err != nil {
		return "", nil, err
	}
	sha, out = s.ScanBytes(data)
	for i := range out {
		out[i].Path = path
	}
	s.mu.Lock()
	if len(s.cache) > 50000 {
		s.cache = map[string]cacheEntry{}
	}
	s.cache[path] = cacheEntry{size: st.Size(), mtime: mt, sha: sha, matches: out}
	s.mu.Unlock()
	return sha, out, nil
}

// ScanTree walks root and calls fn for every match. Unreadable files are skipped.
func (s *Scanner) ScanTree(root string, fn func(Match)) (files int, err error) {
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p == "/proc" || p == "/sys" || p == "/dev" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		_, ms, err := s.ScanFile(p)
		if err != nil {
			return nil
		}
		files++
		for _, m := range ms {
			fn(m)
		}
		return nil
	})
	return files, err
}
