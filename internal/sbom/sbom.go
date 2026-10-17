// Package sbom generates a Software Bill of Materials for ElevateCLI and the
// Go modules it depends on. Output is deterministic (components sorted by name
// and version) so it can be diffed and reproduced across builds. CycloneDX and
// SPDX JSON are supported.
package sbom

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

// SubjectName is the application described by generated SBOMs.
const SubjectName = "github.com/jibankumarpanda/ElevateCLI.0/cmd/elevated-cli"

// Component is a single SBOM entry.
type Component struct {
	Name    string
	Version string
	// Type is "library" (dependency) or "application" (the root subject).
	Type string
}

// FromGoMod parses `require` directives from go.mod content into components.
// It is the fallback used when build metadata is unavailable (for example when
// running under `go run`), and it records both direct and indirect modules.
func FromGoMod(content string) []Component {
	var out []Component
	inBlock := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		if !inBlock {
			if !strings.HasPrefix(line, "require ") {
				continue
			}
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out = append(out, Component{Name: fields[0], Version: fields[1], Type: "library"})
	}
	return out
}

// FromBuildInfo extracts dependency components from Go build metadata. It
// returns nil when build info is unavailable (e.g. under `go run`).
func FromBuildInfo(bi *debug.BuildInfo) []Component {
	if bi == nil {
		return nil
	}
	var out []Component
	for _, dep := range bi.Deps {
		v := dep.Version
		if dep.Replace != nil {
			v = dep.Replace.Version
			if v == "" {
				v = "(replaced)"
			}
		}
		out = append(out, Component{Name: dep.Path, Version: v, Type: "library"})
	}
	return out
}

// Sorted returns a copy of the components ordered by name then version and
// de-duplicated, giving stable output.
func Sorted(components []Component) []Component {
	seen := map[string]bool{}
	var out []Component
	for _, c := range components {
		key := c.Name + "@" + c.Version
		if c.Name == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// Generate renders an SBOM in the requested format ("cyclonedx" or "spdx").
// created is embedded for provenance; pass a zero time to omit timestamps for
// reproducible output.
func Generate(format, subjectVersion string, components []Component, created time.Time) ([]byte, error) {
	comps := Sorted(components)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "cyclonedx", "cdx":
		return cycloneDX(subjectVersion, comps, created)
	case "spdx":
		return spdx(subjectVersion, comps, created)
	default:
		return nil, fmt.Errorf("unknown SBOM format %q (want cyclonedx or spdx)", format)
	}
}

func purl(c Component) string {
	return fmt.Sprintf("pkg:golang/%s@%s", c.Name, c.Version)
}

func cycloneDX(subjectVersion string, comps []Component, created time.Time) ([]byte, error) {
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"tool": map[string]any{
				"vendor":  "ElevateCLI",
				"name":    "elevated-cli",
				"version": subjectVersion,
			},
			"component": map[string]any{
				"type":    "application",
				"name":    SubjectName,
				"version": subjectVersion,
			},
		},
		"components": cdxComponents(comps),
	}
	if !created.IsZero() {
		doc["metadata"].(map[string]any)["timestamp"] = created.UTC().Format("2006-01-02T15:04:05Z")
	}
	return marshal(doc)
}

func cdxComponents(comps []Component) []map[string]any {
	out := make([]map[string]any, 0, len(comps))
	for _, c := range comps {
		out = append(out, map[string]any{
			"type":    "library",
			"name":    c.Name,
			"version": c.Version,
			"purl":    purl(c),
		})
	}
	return out
}

func spdx(subjectVersion string, comps []Component, created time.Time) ([]byte, error) {
	createdStr := ""
	if !created.IsZero() {
		createdStr = created.UTC().Format("2006-01-02T15:04:05Z")
	}
	packages := make([]map[string]any, 0, len(comps))
	for i, c := range comps {
		packages = append(packages, map[string]any{
			"name":             c.Name,
			"SPDXID":           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			"versionInfo":      c.Version,
			"downloadLocation": "NOASSERTION",
			"externalRefs": []map[string]any{{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceType":     "purl",
				"referenceLocator":  purl(c),
			}},
		})
	}
	doc := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              SubjectName,
		"documentNamespace": "https://elevatecli.dev/sbom/" + subjectVersion,
		"creationInfo": map[string]any{
			"created":  createdStr,
			"creators": []string{"Tool: elevated-cli-" + subjectVersion},
		},
		"packages": packages,
	}
	return marshal(doc)
}

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
