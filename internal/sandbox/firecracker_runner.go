package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// firecrackerBinary is the name of the Firecracker CLI binary. It is a
// package-level var so tests can exercise the missing-binary path.
var firecrackerBinary = "firecracker"

// kvmDevice is the device Firecracker requires to boot a microVM.
const kvmDevice = "/dev/kvm"

// MicroVM images are supplied out-of-band (a kernel image and a root
// filesystem). The runner locates them via these environment variables so the
// diagnosis reported when the boundary is unavailable is actionable.
var (
	microVMKernel = os.Getenv("ELEVATED_CLI_FIRECRACKER_KERNEL")
	microVMRootFS = os.Getenv("ELEVATED_CLI_FIRECRACKER_ROOTFS")
)

// kvmOpen is a package var so tests can simulate an un-writable KVM device.
var kvmOpen = func(p string) (*os.File, error) { return os.OpenFile(p, os.O_RDWR, 0) }

// FirecrackerRunner is the microVM execution backend.
//
// MicroVM orchestration is not implemented yet. Selecting sandbox.mode:
// firecracker must therefore fail closed and never silently degrade to host
// os/exec execution: the process runner does not provide the hardware-level
// isolation boundary that a requested microVM promises. The pipeline treats a
// required-but-unavailable sandbox as ANALYSIS_INCOMPLETE, surfacing the
// missing hardening in the report instead of pretending execution happened
// inside a microVM.
type FirecrackerRunner struct {
	Limits ResourceLimits
}

// NewFirecrackerRunner creates a FirecrackerRunner with the given resource limits.
func NewFirecrackerRunner(limits ResourceLimits) *FirecrackerRunner {
	return &FirecrackerRunner{Limits: limits}
}

// FirecrackerDiagnostics reports the state of every host prerequisite for
// booting a Firecracker microVM. It bridges the gap between "fail closed" and
// the operator: when the boundary is unavailable the message lists precisely
// what is missing and what to provision.
type FirecrackerDiagnostics struct {
	Linux              bool
	KVMDevice          string
	KVMAccessible      bool
	KVMError           string
	BinaryPresent      bool
	BinaryPath         string
	BinaryVersion      string
	KernelImage        string
	KernelImagePresent bool
	RootFSImage        string
	RootFSImagePresent bool

	Ready    bool
	Problems []string
}

// Preflight probes the host for every microVM prerequisite without running any
// user code. Ready is true only when Linux + KVM + firecracker + kernel image
// + root filesystem are all present; otherwise Problems lists every failing
// prerequisite so the operator knows exactly what to provision.
func (fr *FirecrackerRunner) Preflight() FirecrackerDiagnostics {
	d := FirecrackerDiagnostics{
		KVMDevice:   kvmDevice,
		KernelImage: microVMKernel,
		RootFSImage: microVMRootFS,
	}

	d.Linux = runtime.GOOS == "linux"
	if !d.Linux {
		d.Problems = append(d.Problems,
			fmt.Sprintf("microVM execution is only supported on Linux (current GOOS=%s)", runtime.GOOS))
	}

	if pathExists(kvmDevice) {
		f, err := kvmOpen(kvmDevice)
		if err != nil {
			d.KVMError = err.Error()
			d.Problems = append(d.Problems,
				fmt.Sprintf("%s exists but is not accessible to this user (%v): add the user to the kvm group", kvmDevice, err))
		} else {
			d.KVMAccessible = true
			_ = f.Close()
		}
	} else {
		d.Problems = append(d.Problems,
			fmt.Sprintf("%s is missing: KVM is required to boot a microVM", kvmDevice))
	}

	if p, err := exec.LookPath(firecrackerBinary); err != nil {
		d.Problems = append(d.Problems,
			fmt.Sprintf("the %q binary was not found in PATH: install Firecracker 1.1+ (https://github.com/firecracker-microvm/firecracker)", firecrackerBinary))
	} else {
		d.BinaryPresent = true
		d.BinaryPath = p
		if v, err := probeFirecrackerVersion(thisBinary(p)); err != nil {
			d.Problems = append(d.Problems, fmt.Sprintf("firecracker version probe failed: %v", err))
		} else {
			d.BinaryVersion = v
		}
	}

	if d.KernelImage == "" {
		d.Problems = append(d.Problems,
			"no microVM kernel image configured: set ELEVATED_CLI_FIRECRACKER_KERNEL to a vmlinux image")
	} else if pathExists(d.KernelImage) {
		d.KernelImagePresent = true
	} else {
		d.Problems = append(d.Problems, fmt.Sprintf("kernel image %q does not exist", d.KernelImage))
	}

	if d.RootFSImage == "" {
		d.Problems = append(d.Problems,
			"no microVM root filesystem configured: set ELEVATED_CLI_FIRECRACKER_ROOTFS to a rootfs image")
	} else if pathExists(d.RootFSImage) {
		d.RootFSImagePresent = true
	} else {
		d.Problems = append(d.Problems, fmt.Sprintf("root filesystem image %q does not exist", d.RootFSImage))
	}

	d.Ready = len(d.Problems) == 0
	return d
}

// Summary renders the diagnostics as a single actionable message.
func (d FirecrackerDiagnostics) Summary() string {
	if d.Ready {
		return fmt.Sprintf("host ready for microVMs: firecracker %q (KVM %s)", d.BinaryVersion, d.KVMDevice)
	}
	return strings.Join(d.Problems, "; ")
}

// thisBinary is a tiny indirection so the version probe is trivially
// replaceable in tests via probeFirecrackerVersion.
func thisBinary(p string) string { return p }

// probeFirecrackerVersion returns the installed firecracker version string.
// It is a package var so tests can inject the "binary present but broken"
// path without shelling out.
var probeFirecrackerVersion = func(binary string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Run fails closed. It returns an error describing the missing enforcement
// rather than running the code on the host. A caller must treat any error from
// Run as "the requested microVM boundary is not available" and mark the
// analysis incomplete.
func (fr *FirecrackerRunner) Run(ctx context.Context, code, lang string) (security.SandboxResult, error) {
	if err := ctx.Err(); err != nil {
		return security.SandboxResult{}, err
	}

	diags := fr.Preflight()
	if !diags.Ready {
		return security.SandboxResult{}, fmt.Errorf(
			"firecracker microVM boundary unavailable (%s); refused to fall back to host process execution",
			diags.Summary())
	}

	// Every host prerequisite is present (Linux, KVM, firecracker, kernel and
	// rootfs images), but microVM orchestration via firecracker-go-sdk is not
	// implemented yet. Fail closed regardless so a requested hardware-level
	// boundary is never replaced with host os/exec.
	return security.SandboxResult{}, fmt.Errorf(
		"firecracker microVM orchestration is not yet implemented; refused to fall back to host process execution (host prerequisites satisfied: %s)",
		diags.Summary())
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func firecrackerNotInstalled() bool {
	_, err := exec.LookPath(firecrackerBinary)
	return err != nil
}