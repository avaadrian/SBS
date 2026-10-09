package bench

import (
	"os/exec"
	"testing"
)

// TestHeldout2ScenariosShape checks the held-out v2 set is well formed:
// non-empty, every scenario fully described with at least one Expect entry and
// a Run, and names that are unique and disjoint from BOTH the built-in set and
// the first held-out set.
func TestHeldout2ScenariosShape(t *testing.T) {
	hs := HeldoutScenarios2()
	if len(hs) == 0 {
		t.Fatal("HeldoutScenarios2 returned no scenarios")
	}

	// Names used by the other two sets. HeldoutScenarios() is PATH-filtered, so
	// also fold in every heldoutCandidate name to catch a collision with a
	// first-set scenario that happens to be filtered out in this environment.
	other := map[string]bool{}
	for _, s := range Scenarios() {
		other[s.Name] = true
	}
	for _, c := range heldoutCandidates() {
		other[c.sc.Name] = true
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
			t.Errorf("%s: duplicate name in held-out v2 set", s.Name)
		}
		seen[s.Name] = true
		if other[s.Name] {
			t.Errorf("%s: name also used by the built-in or first held-out set (not disjoint)", s.Name)
		}
	}
}

// TestHeldout2Disjoint independently confirms every heldout2 candidate name
// (filtered or not) is distinct from every candidate name in the first set,
// so the two held-out suites can never overlap regardless of what is installed.
func TestHeldout2Disjoint(t *testing.T) {
	first := map[string]bool{}
	for _, c := range heldoutCandidates() {
		first[c.sc.Name] = true
	}
	builtin := map[string]bool{}
	for _, s := range Scenarios() {
		builtin[s.Name] = true
	}
	seen := map[string]bool{}
	for _, c := range heldout2Candidates() {
		if first[c.sc.Name] {
			t.Errorf("%s: candidate name collides with the first held-out set", c.sc.Name)
		}
		if builtin[c.sc.Name] {
			t.Errorf("%s: candidate name collides with the built-in set", c.sc.Name)
		}
		if seen[c.sc.Name] {
			t.Errorf("%s: duplicate candidate name", c.sc.Name)
		}
		seen[c.sc.Name] = true
	}
}

// TestHeldout2ToolFiltering checks the LookPath gating: a tool-dependent
// scenario appears in the returned set only when its binary is present, and the
// output is exactly the candidates whose tool resolves (or needs none).
func TestHeldout2ToolFiltering(t *testing.T) {
	cands := heldout2Candidates()
	if len(cands) == 0 {
		t.Fatal("heldout2Candidates returned nothing")
	}

	returned := map[string]bool{}
	for _, s := range HeldoutScenarios2() {
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
