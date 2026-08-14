package sandbox

import "time"

// ResourceLimits defines the constraints for the sandbox environment.
type ResourceLimits struct {
	MemoryMB int
	CPUPerc  int
	Timeout  time.Duration
	AllowNet bool
}

func DefaultLimits() ResourceLimits {
	return ResourceLimits{
		MemoryMB: 256,
		CPUPerc:  50,
		Timeout:  10 * time.Second,
		AllowNet: false,
	}
}
