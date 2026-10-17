package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/logger"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	"go.uber.org/zap"
)

// pluginTimeout bounds a single external analyzer invocation so a hung plugin
// cannot stall the pipeline.
const pluginTimeout = 30 * time.Second

// runPlugins executes every configured external analyzer that applies to the
// language and merges its findings. The analyzer receives the generated code on
// stdin and must emit a JSON array of findings (the sec.Finding shape) on
// stdout.
//
// Plugins are treated as a mandatory SAST stage: if an applicable analyzer
// cannot be executed or returns malformed output, the error is propagated so
// the pipeline marks the analysis incomplete rather than clean. Plugins run
// out-of-process and never on the host with elevated privileges.
func runPlugins(ctx context.Context, plugins []config.PluginAnalyzer, code, language string) ([]sec.Finding, error) {
	if len(plugins) == 0 {
		return nil, nil
	}
	log := logger.WithStage("sast")
	var findings []sec.Finding

	for _, p := range plugins {
		if p.Command == "" || !pluginMatchesLanguage(p, language) {
			continue
		}
		out, err := runPlugin(ctx, p, code, language)
		if err != nil {
			log.Warn("plugin analyzer failed", zap.String("plugin", p.Name), zap.Error(err))
			return findings, fmt.Errorf("plugin analyzer %q failed: %w", p.Name, err)
		}
		var decoded []sec.Finding
		if err := json.Unmarshal(out, &decoded); err != nil {
			return findings, fmt.Errorf("plugin analyzer %q returned invalid JSON: %w", p.Name, err)
		}
		for i := range decoded {
			if decoded[i].Source == "" {
				decoded[i].Source = "plugin:" + pluginName(p)
			}
		}
		findings = append(findings, decoded...)
	}
	return findings, nil
}

func pluginMatchesLanguage(p config.PluginAnalyzer, language string) bool {
	if len(p.Languages) == 0 {
		return true
	}
	want := strings.ToLower(strings.TrimSpace(language))
	for _, l := range p.Languages {
		if strings.ToLower(strings.TrimSpace(l)) == want {
			return true
		}
	}
	return false
}

func pluginName(p config.PluginAnalyzer) string {
	if p.Name != "" {
		return p.Name
	}
	return p.Command
}

func runPlugin(ctx context.Context, p config.PluginAnalyzer, code, language string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, pluginTimeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, p.Command, p.Args...) // #nosec G204 -- operator-configured analyzer
	cmd.Stdin = strings.NewReader(code)
	cmd.Env = append(cmd.Environ(), "ELEVATED_CLI_LANGUAGE="+language)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
