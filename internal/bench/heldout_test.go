package bench

import (
	"os/exec"
	"testing"
)

// TestHeldoutScenariosShape checks the held-out set is well formed: non-empty,
// every scenario fully described with at least one Expect entry and a Run, and
// names that are unique and disjoint from the built-in set.
func TestHeldoutScenariosShape(t *testing.T) {
	hs := HeldoutScenarios()
	if len(hs) == 0 {
		t.Fatal("HeldoutScenarios returned no scenarios")
	}

	builtin := map[string]bool{}
	for _, s := range Scenarios() {
		builtin[s.Name] = true
	}

	seen := map[string]bool{}
	for _, s := range hs {
		switch {
		case s.Name == "":
			t.Error("scenario with empty Name")
		case s.Technique == "":
			t.Errorf("%s: empty Technique", s.Name)
		case s.Tactic == "":
			t.Errorf("%s: empty Tactic", s.Name)
		case len(s.Expect) == 0:
			t.Errorf("%s: no Expect entries", s.Name)
		case s.Run == nil:
			t.Errorf("%s: nil Run", s.Name)
		}
		if seen[s.Name] {
			t.Errorf("%s: duplicate name in held-out set", s.Name)
		}
		seen[s.Name] = true
		if builtin[s.Name] {
			t.Errorf("%s: name also used by the built-in set (not disjoint)", s.Name)
		}
	}
}

// TestHeldoutToolFiltering checks the LookPath gating: a tool-dependent scenario
// appears in the returned set only when its binary is present, and the output is
// exactly the candidates whose tool resolves (or needs none).
func TestHeldoutToolFiltering(t *testing.T) {
	cands := heldoutCandidates()
	if len(cands) == 0 {
		t.Fatal("heldoutCandidates returned nothing")
	}

	returned := map[string]bool{}
	for _, s := range HeldoutScenarios() {
		returned[s.Name] = true
	}

	for _, c := range cands {
		present := c.tool == ""
		if c.tool != "" {
			if _, err := exec.LookPath(c.tool); err == nil {
				present = true
			}
		}
		switch {
		case present && !returned[c.sc.Name]:
			t.Errorf("%s: tool %q resolves but scenario was filtered out", c.sc.Name, c.tool)
		case !present && returned[c.sc.Name]:
			t.Errorf("%s: tool %q is absent but scenario was returned", c.sc.Name, c.tool)
		}
	}

	// Every returned tool-dependent scenario must name a resolvable binary.
	tool := map[string]string{}
	for _, c := range cands {
		tool[c.sc.Name] = c.tool
	}
	for name := range returned {
		if b := tool[name]; b != "" {
			if _, err := exec.LookPath(b); err != nil {
				t.Errorf("%s: returned despite missing tool %q", name, b)
			}
		}
	}
}
