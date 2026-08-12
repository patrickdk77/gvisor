// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package specutils

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
)

// AppArmor mediates accesses made by the confined process against the
// host kernel. The application's system calls are serviced by the
// Sentry and never reach the host kernel, so an AppArmor profile can
// only confine the Sentry and Gofer processes themselves, i.e. the
// host accesses made on the sandboxed application's behalf.
//
// Consequences for profile authors:
//
//   - Paths are those of the confining process, resolved relative to
//     its mount namespace root (AppArmor uses d_absolute_path(), not
//     the process's chroot). The container's root filesystem is
//     mounted at /root in the Gofer's mount namespace, so a container
//     path /etc/foo is mediated as /root/etc/foo.
//
//   - The profile must permit what the Sentry and Gofer themselves
//     need, which is a superset of what the sandboxed application
//     needs. In particular, unix socket permissions are the union of
//     a profile's unix rules and anonymous sockets are mediated by
//     them, so a profile that mentions unix at all must allow the
//     Sentry/Gofer lisafs socketpair or the sandbox cannot start.
//
//   - Profiles generally need the attach_disconnected flag: the Gofer
//     runs in a private mount namespace, so AppArmor considers its
//     paths disconnected from the namespace root.
//
// Profiles are entered with AppArmor's change_onexec mechanism, the
// same one runc uses, rather than by transitioning in place. An
// in-place transition is not usable here: an AppArmor label lives in a
// task's credentials, and the kernel only lets a task write its own
// procattr file (proc_pid_attr_write() returns EACCES when
// current != task), so a multithreaded Go process cannot confine all
// of its threads that way. change_onexec applies the label to the
// whole process at the next exec instead, which is why the caller must
// arrange to re-exec.
const (
	// apparmorEnabledPath reports whether the host kernel has
	// AppArmor enabled.
	apparmorEnabledPath = "/sys/module/apparmor/parameters/enabled"

	// apparmorExecAttrPath is the LSM-specific procattr file used to
	// set the profile to enter at the next exec. Writing
	// "exec <name>" arms the transition.
	apparmorExecAttrPath = "/proc/self/attr/apparmor/exec"

	// apparmorLegacyExecAttrPath is the pre-LSM-stacking location of
	// the same interface, used as a fallback.
	apparmorLegacyExecAttrPath = "/proc/self/attr/exec"

	// apparmorCurrentAttrPath reports the process's current label.
	apparmorCurrentAttrPath = "/proc/self/attr/apparmor/current"

	// apparmorLegacyCurrentAttrPath is the pre-LSM-stacking location of
	// the same interface, used as a fallback.
	apparmorLegacyCurrentAttrPath = "/proc/self/attr/current"
)

// AppArmorProfile holds the state needed to enter an AppArmor profile
// at the next exec.
//
// The two-phase API exists because the interfaces used to arm the
// transition live in /proc and /sys, which are not reachable once the
// process has chroot'ed into the sandbox's empty root, while the
// transition must not take effect until privileged setup (mounting,
// for instance) is done. Prepare() therefore holds the control file
// open across the chroot, and SetOnExec() arms the transition
// immediately before the caller re-execs.
type AppArmorProfile struct {
	name string
	f    *os.File
}

// appArmorEnabled returns true if the host kernel has AppArmor
// enabled. It must be called before chroot.
func appArmorEnabled() bool {
	buf, err := os.ReadFile(apparmorEnabledPath)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(buf)) == "Y"
}

// PrepareAppArmorProfile validates that the named profile can be
// entered and opens the kernel interface used to enter it. It must be
// called before the process chroot's. It returns nil (and no error) if
// no profile was requested.
func PrepareAppArmorProfile(profile string) (*AppArmorProfile, error) {
	if profile == "" {
		return nil, nil
	}
	if !appArmorEnabled() {
		return nil, fmt.Errorf("AppArmor profile %q requested but AppArmor is not enabled on the host", profile)
	}
	f, err := os.OpenFile(apparmorExecAttrPath, os.O_WRONLY, 0)
	if err != nil {
		// Kernels without LSM stacking only expose the legacy path.
		legacy, legacyErr := os.OpenFile(apparmorLegacyExecAttrPath, os.O_WRONLY, 0)
		if legacyErr != nil {
			return nil, fmt.Errorf("opening AppArmor interface for profile %q: %w (legacy path: %v)", profile, err, legacyErr)
		}
		f = legacy
	}
	return &AppArmorProfile{name: profile, f: f}, nil
}

// LogAppArmorLabel logs the calling process's current AppArmor label,
// so that confinement can be confirmed from the logs. It must be called
// before chroot, and is best-effort: a process that cannot read its own
// label logs nothing.
func LogAppArmorLabel(who string) {
	buf, err := os.ReadFile(apparmorCurrentAttrPath)
	if err != nil {
		buf, err = os.ReadFile(apparmorLegacyCurrentAttrPath)
		if err != nil {
			return
		}
	}
	log.Infof("%s AppArmor label: %s", who, strings.TrimSpace(string(buf)))
}

// SetOnExec arms the profile transition for the next exec performed by
// the calling thread, which must be the thread that execs: the pending
// profile is recorded in the task's context, not shared across the
// process. The calling goroutine is therefore locked to its thread and
// deliberately left locked, so the caller must exec (or exit) rather
// than return to normal scheduling.
//
// SetOnExec is a no-op on a nil receiver, i.e. when no profile was
// requested.
func (p *AppArmorProfile) SetOnExec() error {
	if p == nil {
		return nil
	}
	runtime.LockOSThread()
	defer p.f.Close()
	if _, err := p.f.WriteString("exec " + p.name); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("arming AppArmor profile %q for exec: %w", p.name, err)
	}
	log.Infof("Entering AppArmor profile %q on exec", p.name)
	return nil
}
