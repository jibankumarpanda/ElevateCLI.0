package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/metrics"
)

func newMetricsCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Print aggregate scan metrics from the local audit database",
		Long: `Aggregate the local audit database into operational metrics.

Metrics are computed locally and never leave the machine. The default
Prometheus exposition format can be scraped directly; use --format json for
structured output.`,
		Example: `  # Prometheus exposition (default)
  elevated-cli metrics

  # JSON for scripts
  elevated-cli metrics --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openAuditDB(cfg)
			if err != nil {
				return fmt.Errorf("opening audit database: %w", err)
			}
			defer db.Close() //nolint:errcheck

			summary, err := db.Metrics(context.Background())
			if err != nil {
				return fmt.Errorf("collecting metrics: %w", err)
			}
			out, err := metrics.Render(summary, format)
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), out)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "prometheus", "output format: prometheus | json")
	return cmd
}
