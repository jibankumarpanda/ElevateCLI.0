package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Build metadata, populated at startup from the main package's ldflags-injected
// variables via SetBuildInfo. Defaults match an unversioned local build.
var (
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

// SetBuildInfo records the version, commit, and build date so they can be
// surfaced by `elevated-cli version` and `elevated-cli --version`. It is called
// from main.go, where the values are injected with -ldflags.
func SetBuildInfo(version, commit, date string) {
	if version != "" {
		buildVersion = version
	}
	if commit != "" {
		buildCommit = commit
	}
	if date != "" {
		buildDate = date
	}
	RootCmd.Version = fmt.Sprintf("%s (commit %s, built %s)", buildVersion, buildCommit, buildDate)
}

// versionString returns the human-readable build description. The output format
// honours the global --output flag so it can be scripted as JSON.
func versionString() string {
	if viper.GetString("output.format") == "json" {
		return fmt.Sprintf(`{"version":%q,"commit":%q,"date":%q}`, buildVersion, buildCommit, buildDate)
	}
	return fmt.Sprintf("elevated-cli %s (commit %s, built %s)", buildVersion, buildCommit, buildDate)
}

// ─── version command ──────────────────────────────────────────────────────────

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), versionString())
			return nil
		},
	}
}
