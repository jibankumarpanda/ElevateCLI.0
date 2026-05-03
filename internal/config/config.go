package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	AI struct {
		Provider string `mapstructure:"provider"`
		Model    string `mapstructure:"model"`
		APIKey   string `mapstructure:"api_key"`
		Endpoint string `mapstructure:"endpoint"` // For Ollama
	} `mapstructure:"ai"`
	Database struct {
		Path string `mapstructure:"path"`
	} `mapstructure:"database"`
	Sandbox struct {
		Mode string `mapstructure:"mode"` // process, firecracker, docker
	} `mapstructure:"sandbox"`
	Policy struct {
		File  string `mapstructure:"file"`
		Rules struct {
			BlockedImports         []string `mapstructure:"blocked_imports"`
			BlockedFunctions       []string `mapstructure:"blocked_functions"`
			RequireErrorHandling   bool     `mapstructure:"require_error_handling"`
			MaxCyclomaticComplexity int     `mapstructure:"max_cyclomatic_complexity"`
		} `mapstructure:"rules"`
	} `mapstructure:"policy"`
}

func LoadConfig() (*Config, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("ai.provider", "openai")
	v.SetDefault("ai.model", "gpt-4o")
	v.SetDefault("ai.endpoint", "http://localhost:11434")
	v.SetDefault("database.path", "secure-ai.db")
	v.SetDefault("sandbox.mode", "process")
	v.SetDefault("policy.file", ".secure-ai.yaml")

	// Config file locations
	v.SetConfigName(".secure-ai")
	v.SetConfigType("yaml")
	v.AddConfigPath(".") // Project level

	home, err := os.UserHomeDir()
	if err == nil {
		v.AddConfigPath(home) // User level (~/.secure-ai.yaml)
	}

	// Environment variables
	v.AutomaticEnv()
	v.SetEnvPrefix("SECURE_AI")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
		// Config file not found is fine, we use defaults or env vars
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Ensure database path is absolute or relative to a sensible place
	if cfg.Database.Path == "secure-ai.db" {
		cfg.Database.Path = filepath.Join(".", cfg.Database.Path)
	}

	return &cfg, nil
}
