package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/sbom"
)

func newSBOMCmd() *cobra.Command {
	var (
		format    string
		output    string
		moduleDir string
	)

	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Generate a Software Bill of Materials for the tool and its dependencies",
		Long: `Generate an SBOM describing elevated-cli and the Go modules it depends on.

Dependencies are read from the running binary's build metadata when available,
falling back to the module's go.mod. Output is deterministic so it can be
attached to a release and diffed across builds.`,
		Example: `  # CycloneDX to stdout
  elevated-cli sbom

  # SPDX written to a file
  elevated-cli sbom --format spdx --output sbom.spdx.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format == "" {
				format = cfg.SBOM.Format
			}
			if output == "" {
				output = cfg.SBOM.Output
			}

			components := sbom.FromBuildInfo(buildInfo())
			if len(components) == 0 {
				modPath := filepath.Join(moduleDir, "go.mod")
				data, err := os.ReadFile(modPath) // #nosec G304 -- operator-supplied module dir
				if err != nil {
					return fmt.Errorf("no build metadata and cannot read %s: %w", modPath, err)
				}
				components = sbom.FromGoMod(string(data))
			}

			doc, err := sbom.Generate(format, buildVersion, components, sourceDateEpoch())
			if err != nil {
				return err
			}
			if output == "" || output == "-" {
				fmt.Fprint(cmd.OutOrStdout(), string(doc))
				return nil
			}
			// #nosec G703,G306 -- output is an operator-supplied path (from the
			// CLI or config); writing the SBOM there is the feature, and the
			// file is created with owner-only permissions.
			if err := os.WriteFile(output, doc, 0o600); err != nil {
				return fmt.Errorf("writing SBOM to %s: %w", output, err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s SBOM (%d components) to %s\n", format, len(components), output)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "", "SBOM format: cyclonedx | spdx (default from config)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output path, or - for stdout (default from config)")
	cmd.Flags().StringVar(&moduleDir, "module-dir", ".", "directory containing go.mod (fallback source)")
	return cmd
}

// buildInfo returns the embedded build metadata, or nil when unavailable.
func buildInfo() *debug.BuildInfo {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return bi
}

// sourceDateEpoch returns the timestamp to embed in the SBOM. When
// SOURCE_DATE_EPOCH is set the value is honoured for reproducible output;
// otherwise the current time is used.
func sourceDateEpoch() time.Time {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(secs, 0).UTC()
		}
	}
	return time.Now()
}
