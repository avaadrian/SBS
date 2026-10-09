// Package rules implements a small Sigma-style detection rule engine.
//
// A rule matches one event type and a condition tree of all/any/not nodes
// whose leaves compare an event field against one or more values:
//
//   - id: SBS-PROC-001
//     title: Download piped to shell
//     severity: high
//     mitre: [T1059.004]
//     event: process
//     match:
//     all:
//   - field: process.cmdline
//     op: regex
//     value: '(curl|wget)[^|]*\|\s*(ba|da|z)?sh'
package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/avaadrian/sbs/internal/event"
	"gopkg.in/yaml.v3"
)

// Rule is one detection.
type Rule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	MITRE       []string `yaml:"mitre"`
	Event       string   `yaml:"event"`
	Disabled    bool     `yaml:"disabled"`
	Match       Cond     `yaml:"match"`
}

// Cond is a node in a rule's condition tree. Exactly one of All, Any, Not or
// Field must be set.
type Cond struct {
	All    []Cond `yaml:"all"`
	Any    []Cond `yaml:"any"`
	Not    *Cond  `yaml:"not"`
	Field  string `yaml:"field"`
	Op     string `yaml:"op"`
	Value  Values `yaml:"value"`
	NoCase bool   `yaml:"nocase"`

	re []*regexp.Regexp
}

// Values accepts either a scalar or a list in YAML.
type Values []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (v *Values) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*v = Values{n.Value}
		return nil
	case yaml.SequenceNode:
		var s []string
		if err := n.Decode(&s); err != nil {
			return err
		}
		*v = s
		return nil
	}
	return fmt.Errorf("line %d: value must be a string or a list of strings", n.Line)
}

var validOps = map[string]bool{
	"equals": true, "contains": true, "startswith": true, "endswith": true, "regex": true, "exists": true,
}

var validSeverity = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

func (c *Cond) compile(path string) error {
	set := 0
	for _, b := range []bool{len(c.All) > 0, len(c.Any) > 0, c.Not != nil, c.Field != ""} {
		if b {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("%s: condition must set exactly one of all/any/not/field", path)
	}
	for i := range c.All {
		if err := c.All[i].compile(fmt.Sprintf("%s.all[%d]", path, i)); err != nil {
			return err
		}
	}
	for i := range c.Any {
		if err := c.Any[i].compile(fmt.Sprintf("%s.any[%d]", path, i)); err != nil {
			return err
		}
	}
	if c.Not != nil {
		return c.Not.compile(path + ".not")
	}
	if c.Field == "" {
		return nil
	}
	if c.Op == "" {
		c.Op = "equals"
	}
	if !validOps[c.Op] {
		return fmt.Errorf("%s: unknown op %q", path, c.Op)
	}
	if c.Op != "exists" && len(c.Value) == 0 {
		return fmt.Errorf("%s: op %q needs a value", path, c.Op)
	}
	if c.Op == "regex" {
		for _, v := range c.Value {
			if c.NoCase {
				v = "(?i)" + v
			}
			re, err := regexp.Compile(v)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			c.re = append(c.re, re)
		}
	} else if c.NoCase {
		for i, v := range c.Value {
			c.Value[i] = strings.ToLower(v)
		}
	}
	return nil
}

func (c *Cond) eval(f map[string]string) bool {
	switch {
	case len(c.All) > 0:
		for i := range c.All {
			if !c.All[i].eval(f) {
				return false
			}
		}
		return true
	case len(c.Any) > 0:
		for i := range c.Any {
			if c.Any[i].eval(f) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !c.Not.eval(f)
	}
	got, ok := f[c.Field]
	if c.Op == "exists" {
		return ok && got != ""
	}
	if c.Op == "regex" {
		for _, re := range c.re {
			if re.MatchString(got) {
				return true
			}
		}
		return false
	}
	if c.NoCase {
		got = strings.ToLower(got)
	}
	for _, v := range c.Value {
		var hit bool
		switch c.Op {
		case "equals":
			hit = got == v
		case "contains":
			hit = strings.Contains(got, v)
		case "startswith":
			hit = strings.HasPrefix(got, v)
		case "endswith":
			hit = strings.HasSuffix(got, v)
		}
		if hit {
			return true
		}
	}
	return false
}

// Engine evaluates a compiled rule set.
type Engine struct {
	rules []*Rule
}

// Parse compiles rules from YAML (a list of rules).
func Parse(data []byte, name string) ([]*Rule, error) {
	var rs []*Rule
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	for _, r := range rs {
		if r.ID == "" || r.Title == "" {
			return nil, fmt.Errorf("%s: every rule needs an id and a title", name)
		}
		if r.Event != event.TypeProcess && r.Event != event.TypeFile {
			return nil, fmt.Errorf("%s: rule %s: event must be %q or %q", name, r.ID, event.TypeProcess, event.TypeFile)
		}
		if r.Severity == "" {
			r.Severity = "medium"
		}
		if !validSeverity[r.Severity] {
			return nil, fmt.Errorf("%s: rule %s: unknown severity %q", name, r.ID, r.Severity)
		}
		if err := r.Match.compile(r.ID + ".match"); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return rs, nil
}

// NewEngine builds an engine, rejecting duplicate rule IDs.
func NewEngine(sets ...[]*Rule) (*Engine, error) {
	e := &Engine{}
	seen := map[string]bool{}
	for _, set := range sets {
		for _, r := range set {
			if seen[r.ID] {
				return nil, fmt.Errorf("duplicate rule id %s", r.ID)
			}
			seen[r.ID] = true
			if !r.Disabled {
				e.rules = append(e.rules, r)
			}
		}
	}
	return e, nil
}

// LoadFS parses every *.yaml / *.yml file in fsys.
func LoadFS(fsys fs.FS) ([]*Rule, error) {
	var all []*Rule
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isYAML(p) {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		rs, err := Parse(data, p)
		all = append(all, rs...)
		return err
	})
	return all, err
}

// LoadPath loads a rule file or every YAML file in a directory.
func LoadPath(path string) ([]*Rule, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return LoadFS(os.DirFS(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

func isYAML(p string) bool {
	ext := filepath.Ext(p)
	return ext == ".yaml" || ext == ".yml"
}

// Len returns the number of active rules.
func (e *Engine) Len() int { return len(e.rules) }

// Evaluate returns an alert for every rule the event matches.
func (e *Engine) Evaluate(ev *event.Event) []*event.Alert {
	var out []*event.Alert
	var fields map[string]string
	for _, r := range e.rules {
		if r.Event != ev.Type {
			continue
		}
		if fields == nil {
			fields = ev.Fields()
		}
		if r.Match.eval(fields) {
			out = append(out, &event.Alert{
				Time:     time.Now().UTC(),
				RuleID:   r.ID,
				Title:    r.Title,
				Severity: r.Severity,
				MITRE:    r.MITRE,
				Event:    ev,
			})
		}
	}
	return out
}
