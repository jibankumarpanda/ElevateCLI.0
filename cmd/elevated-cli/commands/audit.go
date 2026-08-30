package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

func newAuditCmd() *cobra.Command {
	var (
		filePath  string
		dirPath   string
		outFormat string
		language  string
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit an existing file or directory through the security pipeline",
		Example: `  # Audit a single file
  elevated-cli audit --file ./mycode.go

  # Audit all .py files in a directory
  elevated-cli audit --dir ./src --lang python

  # Output results as JSON (pipe to jq, CI/CD, etc.)
  elevated-cli audit --file ./api_handler.go --output json | jq '.final_score'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if filePath == "" && dirPath == "" {
				return fmt.Errorf("either --file or --dir is required")
			}

			outFmt := cfg.Output.Format
			if outFormat != "" {
				outFmt = outFormat
			}

			srcDir := filepath.Dir(filePath)
			if dirPath != "" {
				srcDir = dirPath
			}
			pipeline, err := buildPipeline(*cfg, false, srcDir) // no sandbox for audits by default
			if err != nil {
				return fmt.Errorf("building pipeline: %w", err)
			}

			var files []string
			if filePath != "" {
				files = []string{filePath}
			} else {
				files, err = collectFiles(dirPath, language)
				if err != nil {
					return fmt.Errorf("collecting files: %w", err)
				}
				fmt.Fprintf(os.Stderr, "📂 Found %d files to audit in %s\n", len(files), dirPath)
			}

			var (
				rejected   int
				exitCode   = sec.ExitCodeOK
			)
			for _, f := range files {
				// #nosec G304 -- auditing a user-specified file is the feature;
				// paths come from --file/--dir CLI arguments, not file contents.
				code, err := os.ReadFile(filepath.Clean(f))
				if err != nil {
					fmt.Fprintf(os.Stderr, "⚠  Skipping %s: %v\n", f, err)
					continue
				}

				lang := language
				if lang == "" {
					lang = detectLang(f)
				}

				fmt.Fprintf(os.Stderr, "🔍 Auditing %s (%s)...\n", f, lang)

				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				report, err := pipeline.Run(ctx, fmt.Sprintf("audit of %s", f), string(code), lang, "none", "none")
				cancel()
				if err != nil {
					fmt.Fprintf(os.Stderr, "  Pipeline error: %v\n", err)
					continue
				}

				printReport(report, outFmt, cfg.Output.ShowCode)
				saveAuditRecord(cfg, report)

				// Any hard-stop verdict blocks the file. Track the worst
				// (highest) exit code across all audited files so CI fails as
				// loudly as the most severe unresolved issue.
				if code := sec.ExitCodeFor(report.Verdict); code != sec.ExitCodeOK {
					rejected++
					if code > exitCode {
						exitCode = code
					}
				}
			}

			if rejected > 0 {
				os.Exit(exitCode) // non-zero = one or more files blocked
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to file to audit")
	cmd.Flags().StringVarP(&dirPath, "dir", "d", "", "Path to directory to audit recursively")
	cmd.Flags().StringVarP(&language, "lang", "l", "", "Language override (auto-detected from extension if omitted)")
	cmd.Flags().StringVarP(&outFormat, "output", "o", "", "Output format: rich | json | sarif | plain")

	return cmd
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func collectFiles(dir, lang string) ([]string, error) {
	var exts []string
	if lang != "" {
		exts = []string{langToExtension(lang)}
	} else {
		exts = []string{".go", ".py", ".js", ".ts"}
	}

	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip hidden dirs and vendor
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		for _, e := range exts {
			if ext == e {
				files = append(files, path)
				break
			}
		}
		return nil
	})
	return files, err
}

func detectLang(path string) string {
	switch filepath.Ext(path) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	default:
		return "go"
	}
}

func langToExtension(lang string) string {
	switch strings.ToLower(lang) {
	case "python", "python3":
		return ".py"
	case "javascript", "js":
		return ".js"
	case "typescript", "ts":
		return ".ts"
	default:
		return ".go"
	}
}
