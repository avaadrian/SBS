// Package assets embeds the built-in detection rules and signatures.
package assets

import (
	"embed"
	"io/fs"

	"github.com/avaadrian/sbs/internal/rules"
	"github.com/avaadrian/sbs/internal/scanner"
)

//go:embed rules/*.yaml
var rulesFS embed.FS

//go:embed signatures/*.yaml
var sigsFS embed.FS

// Rules returns the built-in rule set.
func Rules() ([]*rules.Rule, error) {
	sub, _ := fs.Sub(rulesFS, "rules")
	return rules.LoadFS(sub)
}

// Signatures loads the built-in signatures into s.
func Signatures(s *scanner.Scanner) error {
	sub, _ := fs.Sub(sigsFS, "signatures")
	return s.AddFS(sub)
}
