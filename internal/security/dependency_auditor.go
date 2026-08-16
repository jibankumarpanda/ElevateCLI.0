// Stage 2: Dependency audit.
//
// Extracts the dependency/import declarations from generated code and, when a
// project directory with lockfiles is available, runs the configured CVE
// scanners against them:
//
//   - govulncheck (Go modules) — enabled with analysis.govulncheck
//   - osv-scanner (multi-language lockfiles) — enabled with analysis.osv_scanner
//
// Fail-closed contract: a scanner that is enabled but cannot run (binary
// missing, database unreachable) returns an error so the pipeline marks the
// analysis incomplete. A missing scanner must never be reported as a clean
// scan. When no lockfile is present there is genuinely nothing to CVE-scan
// (no version-resolved dependency set), so that case is logged and treated as
// complete rather than fabricated as clean or failed.
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/logger"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	"go.uber.org/zap"
)

// DependencyAuditorImpl implements the DependencyAuditor interface.
type DependencyAuditorImpl struct {
	cfg config.AnalysisConfig
	// Dir is the project directory to search for lockfiles. Empty when the
	// audit target is single generated code with no on-disk module (generate).
	Dir string
}

// NewDependencyAuditor returns a DependencyAuditorImpl using the given
// analysis configuration.
func NewDependencyAuditor(cfg config.AnalysisConfig) *DependencyAuditorImpl {
	return &DependencyAuditorImpl{cfg: cfg}
}

// Audit extracts declared dependencies and checks them for known
// vulnerabilities using the configured scanners.
func (d *DependencyAuditorImpl) Audit(ctx context.Context, code, language string) ([]sec.Vulnerability, error) {
	log := logger.WithStage("deps")

	imports := extractImports(code, language)
	if len(imports) == 0 {
		log.Info("dependency audit: no imports detected")
		return nil, nil
	}
	log.Debug("dependency audit: imports extracted", zap.Int("count", len(imports)))

	// Code-only mode (generate): no lockfile, no version-resolved dependency
	// set, so there is nothing to CVE-scan. This is not an analysis failure.
	if d.Dir == "" {
		log.Info("dependency audit: no project directory supplied — " +
			"CVE scan skipped (no lockfile). Run `elevated-cli audit` on a project to scan dependencies.")
		return nil, nil
	}

	lockfiles := filterRedundant(findLockfiles(d.Dir))
	if len(lockfiles) == 0 {
		log.Info("dependency audit: no lockfiles found — nothing to CVE-scan",
			zap.String("dir", d.Dir))
		return nil, nil
	}

	var vulns []sec.Vulnerability
	for _, lf := range lockfiles {
		v, err := d.scanLockfile(ctx, lf)
		if err != nil {
			// Fail closed: an enabled scanner that could not run is an
			// incomplete analysis, never a clean scan.
			return vulns, err
		}
		vulns = append(vulns, v...)
	}

	log.Info("dependency audit complete", zap.Int("vulnerabilities", len(vulns)))
	return vulns, nil
}

// ─── Lockfile discovery ───────────────────────────────────────────────────────

// lockfile identifies a discovered dependency manifest and whether it belongs
// to a Go module (which govulncheck can scan directly).
type lockfile struct {
	Path string
	IsGo bool
}

// lockfileNames maps a lockfile basename to whether it is a Go module manifest.
// Every non-Go lockfile here is scanned with osv-scanner.
var lockfileNames = map[string]bool{
	"go.mod":              true,
	"go.sum":              true,
	"package-lock.json":   false,
	"npm-shrinkwrap.json": false,
	"yarn.lock":           false,
	"pnpm-lock.yaml":      false,
	"requirements.txt":    false,
	"Pipfile.lock":        false,
	"poetry.lock":         false,
	"pyproject.toml":      false,
	"Cargo.lock":          false,
	"composer.lock":       false,
	"Gemfile.lock":        false,
}

// findLockfiles walks dir (non-recursive across the scanned root, recursing
// into subdirectories) and returns the lockfiles that scanners can consume.
// The walk skips hidden directories, vendor, and node_modules.
func findLockfiles(dir string) []lockfile {
	var out []lockfile
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != dir && (strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if isGo, ok := lockfileNames[d.Name()]; ok {
			out = append(out, lockfile{Path: path, IsGo: isGo})
		}
		return nil
	})
	return out
}

// filterRedundant drops go.sum files when a go.mod exists in the same
// directory: govulncheck (or osv-scanner on go.mod) already covers the module,
// and osv-scanner cannot extract dependencies from go.sum alone.
func filterRedundant(lfs []lockfile) []lockfile {
	hasGoMod := map[string]bool{}
	for _, lf := range lfs {
		if lf.IsGo && filepath.Base(lf.Path) == "go.mod" {
			hasGoMod[filepath.Dir(lf.Path)] = true
		}
	}
	out := lfs[:0]
	for _, lf := range lfs {
		if lf.IsGo && filepath.Base(lf.Path) == "go.sum" && hasGoMod[filepath.Dir(lf.Path)] {
			continue
		}
		out = append(out, lf)
	}
	return out
}

// ─── Scanner dispatch ─────────────────────────────────────────────────────────

// scanLockfile runs the appropriate scanner for a lockfile.
// govulncheck consumes a Go module (go.mod); osv-scanner consumes lockfiles.
func (d *DependencyAuditorImpl) scanLockfile(ctx context.Context, lf lockfile) ([]sec.Vulnerability, error) {
	if lf.IsGo && filepath.Base(lf.Path) == "go.mod" && d.cfg.Govulncheck {
		return runGovulncheck(ctx, filepath.Dir(lf.Path))
	}
	if d.cfg.OSVScanner {
		return runOSVScanner(ctx, lf.Path)
	}
	return nil, nil
}

// ─── govulncheck integration (Go) ─────────────────────────────────────────────

func runGovulncheck(ctx context.Context, moduleDir string) ([]sec.Vulnerability, error) {
	cmd := exec.CommandContext(ctx, "govulncheck", "-format", "json", "./...")
	cmd.Dir = moduleDir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, runErr := cmd.Output()

	// Missing binary: hard, fail-closed error — the scanner never ran.
	if runErr != nil && errors.Is(runErr, exec.ErrNotFound) {
		return nil, fmt.Errorf("govulncheck binary not found in PATH: %w", runErr)
	}

	// No output at all: only a zero exit is a true clean scan.
	if len(bytes.TrimSpace(out)) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("govulncheck failed: %v: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, nil
	}

	return parseGovulncheck(out)
}

func parseGovulncheck(out []byte) ([]sec.Vulnerability, error) {
	type findingRec struct {
		OSV          string `json:"osv"`
		FixedVersion string `json:"fixed_version"`
		Trace        []struct {
			Module  string `json:"module"`
			Version string `json:"version"`
		} `json:"trace"`
	}

	type osvRec struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
		Summary string   `json:"summary"`
		Details string   `json:"details"`
	}

	osvByID := map[string]osvRec{}
	findings := map[string]findingRec{}

	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var obj map[string]json.RawMessage
		if err := dec.Decode(&obj); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, err
			}
			break
		}
		if raw, ok := obj["finding"]; ok {
			var f findingRec
			if json.Unmarshal(raw, &f) == nil {
				findings[f.OSV] = f
			}
		}
		if raw, ok := obj["osv"]; ok {
			var o osvRec
			if json.Unmarshal(raw, &o) == nil {
				osvByID[o.ID] = o
			}
		}
	}

	// No findings records means no reachable vulnerabilities in the module.
	if len(findings) == 0 {
		return nil, nil
	}

	var vulns []sec.Vulnerability
	for osvID, f := range findings {
		rec := osvByID[osvID]
		desc := rec.Summary
		if desc == "" {
			desc = rec.Details
		}
		id := osvID
		if len(rec.Aliases) > 0 {
			id = rec.Aliases[0] // prefer the CVE number when available
		}

		pkg := ""
		version := ""
		if len(f.Trace) > 0 {
			pkg = f.Trace[0].Module
			version = f.Trace[0].Version
		}
		if pkg == "" {
			pkg = strings.TrimPrefix(osvID, "GO-")
		}

		vulns = append(vulns, sec.Vulnerability{
			ID:           id,
			Package:      pkg,
			Version:      version,
			FixedVersion: f.FixedVersion,
			Severity:     sec.SeverityMedium, // govulncheck does not publish CVSS
			Description:  desc,
			Source:       "govulncheck",
		})
	}
	return vulns, nil
}

// ─── osv-scanner integration (multi-language) ─────────────────────────────────

func runOSVScanner(ctx context.Context, lockfilePath string) ([]sec.Vulnerability, error) {
	// Scope the lockfile to its own directory: the subprocess receives only a
	// basename while cmd.Dir anchors it, so a crafted path can never be parsed
	// as a flag by osv-scanner.
	absPath, err := filepath.Abs(filepath.Clean(lockfilePath))
	if err != nil {
		return nil, fmt.Errorf("resolving lockfile path %q: %w", lockfilePath, err)
	}
	// #nosec G204 -- lockfilePath is produced by findLockfiles while walking a
	// user-supplied directory. It is cleaned, resolved, and reduced to its
	// basename, with cmd.Dir anchoring the process to the parent directory;
	// the basename cannot contain a path separator and is the value of the
	// --lockfile flag, so it can never be parsed as an option.
	cmd := exec.CommandContext(ctx, "osv-scanner", "scan", "--format", "json", "--lockfile", filepath.Base(absPath))
	cmd.Dir = filepath.Dir(absPath)

	// osv-scanner writes progress to stderr; JSON results to stdout only.
	// CombinedOutput would interleave them and corrupt the JSON.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, runErr := cmd.Output()

	if runErr != nil && errors.Is(runErr, exec.ErrNotFound) {
		return nil, fmt.Errorf("osv-scanner binary not found in PATH: %w", runErr)
	}

	if len(bytes.TrimSpace(out)) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("osv-scanner failed: %v: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, nil
	}

	return parseOSVScanner(out)
}

type osvScannerOutput struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID       string   `json:"id"`
				Aliases  []string `json:"aliases"`
				Summary  string   `json:"summary"`
				Details  string   `json:"details"`
				Severity []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				} `json:"severity"`
				Affected []struct {
					Ranges []struct {
						Events []struct {
							Introduced string `json:"introduced"`
							Fixed      string `json:"fixed"`
						} `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

func parseOSVScanner(out []byte) ([]sec.Vulnerability, error) {
	var parsed osvScannerOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("parsing osv-scanner output: %w", err)
	}

	var vulns []sec.Vulnerability
	for _, result := range parsed.Results {
		for _, pkg := range result.Packages {
			for _, v := range pkg.Vulnerabilities {
				cvss := 0.0
				for _, s := range v.Severity {
					if strings.HasPrefix(s.Score, "CVSS:") {
						cvss = cvssBaseScore(s.Score)
						break
					}
				}

				desc := v.Summary
				if desc == "" {
					desc = v.Details
				}
				id := v.ID
				if len(v.Aliases) > 0 {
					id = v.Aliases[0]
				}

				fixed := ""
				for _, a := range v.Affected {
					for _, r := range a.Ranges {
						for _, e := range r.Events {
							if e.Fixed != "" {
								fixed = e.Fixed
							}
						}
					}
				}

				vulns = append(vulns, sec.Vulnerability{
					ID:           id,
					Package:      pkg.Package.Name,
					Version:      pkg.Package.Version,
					FixedVersion: fixed,
					Severity:     severityFromCVSS(cvss),
					CVSS:         math.Round(cvss*10) / 10,
					Description:  desc,
					Source:       "osv-scanner",
				})
			}
		}
	}
	return vulns, nil
}

// ─── CVSS 3.1 base score ──────────────────────────────────────────────────────

// cvssBaseScore computes the CVSS 3.1 base score from a vector string such as
// "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L". Returns 0 for unparseable
// vectors. Deterministic and dependency-free.
func cvssBaseScore(vector string) float64 {
	metrics := map[string]string{}
	idx := strings.LastIndex(vector, "CVSS:3.1/")
	if idx < 0 {
		idx = strings.LastIndex(vector, "CVSS:3.0/")
		if idx < 0 {
			return 0
		}
	}
	for _, part := range strings.Split(vector[idx+8:], "/") {
		if i := strings.Index(part, ":"); i > 0 {
			metrics[part[:i]] = part[i+1:]
		}
	}

	av, ok := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
	if !ok {
		return 0
	}
	ac, ok := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	if !ok {
		return 0
	}
	pr, ok := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
	if !ok {
		return 0
	}
	ui, ok := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	if !ok {
		return 0
	}
	scopeChanged := metrics["S"] == "C"
	if scopeChanged {
		if pr, ok = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[metrics["PR"]]; !ok {
			return 0
		}
	}
	ci := confValue(metrics["C"])
	ii := confValue(metrics["I"])
	ai := confValue(metrics["A"])
	if ci < 0 || ii < 0 || ai < 0 {
		return 0
	}

	iss := 1 - (1-ci)*(1-ii)*(1-ai)
	// CVSS 3.1 Impact uses different formulas depending on scope change:
	//   S:U  Impact = 6.42 * ISS
	//   S:C  Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui
	base := impact + exploitability

	// The spec's Roundup() returns the smallest multiple of 0.1 >= the input
	// (a ceiling, not round-half-up), capped at 10.
	return math.Min(math.Ceil(base*10)/10, 10)
}

func confValue(v string) float64 {
	switch v {
	case "H":
		return 0.56
	case "L":
		return 0.22
	case "N":
		return 0
	default:
		return -1
	}
}

func severityFromCVSS(cvss float64) sec.Severity {
	switch {
	case cvss >= 9.0:
		return sec.SeverityCritical
	case cvss >= 7.0:
		return sec.SeverityHigh
	case cvss >= 4.0:
		return sec.SeverityMedium
	case cvss > 0:
		return sec.SeverityLow
	default:
		return sec.SeverityMedium
	}
}

// ─── Import extraction ────────────────────────────────────────────────────────

// extractImports pulls import/require/using declarations out of code.
func extractImports(code, language string) []string {
	switch strings.ToLower(language) {
	case "go", "golang":
		return goImports(code)
	case "python", "python3":
		return matchRepeated(code, `(?:^|\n)\s*(?:import|from)\s+([\w.]+)`)
	case "javascript", "js", "typescript", "ts":
		return matchRepeated(code, `(?:require|import)\s*\(?\s*(?:[\w\s{},*]+?\s+from\s+)?['"]([^'"]+)['"]`)
	default:
		return nil
	}
}

func goImports(code string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "generated.go", code, parser.ImportsOnly)
	if err != nil {
		return nil
	}
	var out []string
	for _, imp := range f.Imports {
		if imp.Path != nil {
			out = append(out, strings.Trim(imp.Path.Value, `"`))
		}
	}
	return out
}

func matchRepeated(s, pattern string) []string {
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(s, -1)
	var out []string
	for _, m := range matches {
		if len(m) > 1 {
			out = append(out, m[1])
		}
	}
	return out
}
