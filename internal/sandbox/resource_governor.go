package sandbox

import "time"

// ResourceLimits defines the constraints for the sandbox environment.
type ResourceLimits struct {
	MemoryMB int
	CPUPerc  int
	Timeout  time.Duration
	AllowNet bool

	// Extended hard limits enforced by the process runner (P0):
	// MaxCPUSeconds caps CPU time (RLIMIT_CPU), MaxNProc caps the process count
	// (RLIMIT_NPROC, per-UID caveat), MaxOutputKB caps combined captured output,
	// MaxFSWriteMB caps the size a single file may reach (RLIMIT_FSIZE).
	// Zero values mean "no explicit cap" for the rlimit-based controls and "no
	// cap" for output capture.
	MaxCPUSeconds int
	MaxNProc      int
	MaxOutputKB   int
	MaxFSWriteMB  int
}

// DefaultLimits returns the sandbox defaults used when a runner is created
// without explicit values. These are deliberately conservative: no network, a
// bounded memory cap, a short execution timeout, and enforced output and
// filesystem caps.
func DefaultLimits() ResourceLimits {
	return ResourceLimits{
		MemoryMB:     256,
		CPUPerc:      50,
		Timeout:      10 * time.Second,
		AllowNet:     false,
		MaxCPUSeconds: 0,
		MaxNProc:      0,
		MaxOutputKB:   1024,
		MaxFSWriteMB:  10,
	}
}