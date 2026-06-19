package security

import "fmt"

// PipelineError is returned when a verification stage fails unexpectedly.
type PipelineError struct {
	Stage   string
	Message string
	Err     error
}

func (e *PipelineError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Stage, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Stage, e.Message)
}

func (e *PipelineError) Unwrap() error { return e.Err }

// NewPipelineError creates a PipelineError for a given stage.
func NewPipelineError(stage, message string, err error) *PipelineError {
	return &PipelineError{Stage: stage, Message: message, Err: err}
}

// SandboxError is returned when the sandbox fails to execute code.
type SandboxError struct {
	Mode    string
	Message string
	Err     error
}

func (e *SandboxError) Error() string {
	return fmt.Sprintf("sandbox[%s]: %s: %v", e.Mode, e.Message, e.Err)
}

func (e *SandboxError) Unwrap() error { return e.Err }

// ConfigError is returned for invalid configuration values.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("config error [%s]: %s", e.Field, e.Message)
}

// AIProviderError is returned when an LLM API call fails.
type AIProviderError struct {
	Provider string
	Message  string
	Err      error
}

func (e *AIProviderError) Error() string {
	return fmt.Sprintf("ai[%s]: %s: %v", e.Provider, e.Message, e.Err)
}

func (e *AIProviderError) Unwrap() error { return e.Err }
