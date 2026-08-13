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

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// The profile denies one file and audits the denial, so that a record is
// produced. A plain deny rule is silent, which is the point of deny, so it
// would prove nothing here.
const auditTestProfile = `profile auditprofile flags=(attach_disconnected) {
  /** rmix,
  %s/** rw,
  audit deny %s/secret r,
  audit deny %s/link r,
}
`

// setupAuditPolicy writes a policy directory and the file the profile denies.
// The container's root is the host root, so one directory serves both
// --apparmor-policy-source=host and =container.
func setupAuditPolicy(t *testing.T) (dir string) {
	t.Helper()
	dir, err := os.MkdirTemp(testutil.TmpDir(), "apparmor-audit")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	policyDir := filepath.Join(dir, "apparmor.d")
	if err := os.Mkdir(policyDir, 0755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	profile := fmt.Sprintf(auditTestProfile, dir, dir, dir)
	if err := os.WriteFile(filepath.Join(policyDir, "audittest"), []byte(profile), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("secret\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// A file reached through a symlink whose own path the profile refuses to
	// let anything read. readlink(2) has no LSM hook in Linux, so resolving
	// the link must still work, and the access it leads to is mediated
	// against the target. This is the shape that broke in production: every
	// resolution of a root-owned symlink under an owner rule was denied.
	if err := os.WriteFile(filepath.Join(dir, "target"), []byte("target\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	return policyDir
}

// capturedStdio replaces the process's stdout and stderr with pipes. A sandbox
// started without a console socket is given this process's stdout and stderr as
// the container's own, so this is how a test sees what the container sees.
type capturedStdio struct {
	outR, outW *os.File
	errR, errW *os.File
	oldOut     *os.File
	oldErr     *os.File
}

func captureStdio(t *testing.T) *capturedStdio {
	t.Helper()
	c := &capturedStdio{oldOut: os.Stdout, oldErr: os.Stderr}
	var err error
	if c.outR, c.outW, err = os.Pipe(); err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if c.errR, c.errW, err = os.Pipe(); err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout, os.Stderr = c.outW, c.errW
	return c
}

// read restores the process's streams and returns what the container wrote to
// each. The sandbox still holds the write ends, so the reads are bounded by a
// deadline rather than by EOF.
func (c *capturedStdio) read(t *testing.T) (stdout, stderr string) {
	t.Helper()
	os.Stdout, os.Stderr = c.oldOut, c.oldErr
	return drain(t, c.outR), drain(t, c.errR)
}

func (c *capturedStdio) close() {
	os.Stdout, os.Stderr = c.oldOut, c.oldErr
	c.outR.Close()
	c.outW.Close()
	c.errR.Close()
	c.errW.Close()
}

func drain(t *testing.T, r *os.File) string {
	t.Helper()
	if err := r.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var b strings.Builder
	buf := make([]byte, 8192)
	for {
		n, err := r.Read(buf)
		b.Write(buf[:n])
		if err != nil || n == 0 {
			return b.String()
		}
	}
}

const auditRecord = `apparmor="DENIED"`

// TestAppArmorAuditTargets runs a confined container for every combination of
// --apparmor-policy-source and --apparmor-audit-target and checks, in a real
// sandbox, that the profile is enforced and that its records go where the
// configuration says.
//
// Every AppArmor regression so far has been in the wiring rather than in the
// engine: a sink installed before the policy it depends on, a record written to
// a stream nobody drains, an operation mediated that Linux does not mediate.
// None of those are visible to a test that calls one function; they need a
// container that boots, is denied something, and exits.
func TestAppArmorAuditTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		// source is --apparmor-policy-source.
		source string
		// target is --apparmor-audit-target.
		target string
		// wantEnforced is whether the denied file must be unreadable.
		wantEnforced bool
		// wantOn names the stream the record must appear on: "stdout",
		// "stderr", "log", or "" for nowhere.
		wantOn string
	}{
		{
			// The container's own policy is read inside
			// createContainerProcess(), after the audit sink is
			// installed, so this case fails if the sink is
			// conditioned on a policy already being loaded.
			name: "container source to stderr", source: "container", target: "stderr",
			wantEnforced: true, wantOn: "stderr",
		},
		{
			name: "container source to stdout", source: "container", target: "stdout",
			wantEnforced: true, wantOn: "stdout",
		},
		{
			name: "container source to the sentry log", source: "container", target: "gvisor",
			wantEnforced: true, wantOn: "log",
		},
		{
			name: "container source with records off", source: "container", target: "none",
			wantEnforced: true, wantOn: "",
		},
		{
			name: "host source to stderr", source: "host", target: "stderr",
			wantEnforced: true, wantOn: "stderr",
		},
		{
			name: "host source to stdout", source: "host", target: "stdout",
			wantEnforced: true, wantOn: "stdout",
		},
		{
			name: "host source to the sentry log", source: "host", target: "gvisor",
			wantEnforced: true, wantOn: "log",
		},
		{
			name: "host source with records off", source: "host", target: "none",
			wantEnforced: true, wantOn: "",
		},
		{
			// Nothing is mediated and the container's streams are
			// left alone entirely.
			name: "no policy source", source: "none", target: "stderr",
			wantEnforced: false, wantOn: "",
		},
		{
			// An empty target is the default, which is stderr.
			name: "default target", source: "container", target: "",
			wantEnforced: true, wantOn: "stderr",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policyDir := setupAuditPolicy(t)
			base := filepath.Dir(policyDir)
			secret := filepath.Join(base, "secret")

			// Read the denied file, then report what happened. The
			// exit status is 0 either way, so a denial is
			// distinguished by the output rather than by the status.
			link := filepath.Join(base, "link")
			cmd := fmt.Sprintf("readlink %s >/dev/null 2>&1 && cat %s >/dev/null 2>&1 && echo LINKOK || echo LINKFAIL; cat %s >/dev/null 2>&1 && echo READ || echo DENIED", link, link, secret)
			spec := testutil.NewSpecWithArgs("sh", "-c", cmd)
			spec.Process.ApparmorProfile = "auditprofile"

			conf := testutil.TestConfig(t)
			conf.AppArmorPolicySource = tc.source
			conf.AppArmorPolicyDir = policyDir
			conf.AppArmorAuditTarget = tc.target
			// The container's stdio is this process's stdio, so the
			// sentry's own logging must not be pointed at it or the
			// two cannot be told apart.
			conf.Debug = false
			logFile := filepath.Join(base, "sentry.log")
			conf.DebugLog = logFile

			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			args := Args{
				ID:        testutil.RandomContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			}

			stdio := captureStdio(t)
			defer stdio.close()

			c, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer c.Destroy()
			if err := c.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}
			ws, err := c.Wait()
			if err != nil {
				t.Fatalf("error waiting on container: %v", err)
			}
			stdout, stderr := stdio.read(t)
			if ws.ExitStatus() != 0 {
				t.Errorf("container exited with %d; stdout=%q stderr=%q", ws.ExitStatus(), stdout, stderr)
			}

			// Resolving a symlink is never mediated, whatever the
			// policy source, since Linux registers no readlink hook.
			if !strings.Contains(stdout, "LINKOK") {
				t.Errorf("reading a symlink was refused; readlink(2) is not a mediated operation (stdout=%q stderr=%q)", stdout, stderr)
			}

			// Enforcement.
			gotEnforced := strings.Contains(stdout, "DENIED")
			if gotEnforced != tc.wantEnforced {
				t.Errorf("the denied file was refused = %t, want %t (stdout=%q, stderr=%q)",
					gotEnforced, tc.wantEnforced, stdout, stderr)
			}

			// Records, on the stream the configuration names and on
			// no other.
			logData, _ := os.ReadFile(logFile)
			got := map[string]bool{
				"stdout": strings.Contains(stdout, auditRecord),
				"stderr": strings.Contains(stderr, auditRecord),
				"log":    strings.Contains(string(logData), auditRecord),
			}
			for stream, gotIt := range got {
				if want := stream == tc.wantOn; gotIt != want {
					t.Errorf("record on %s = %t, want %t (stdout=%q stderr=%q log=%d bytes)",
						stream, gotIt, want, stdout, stderr, len(logData))
				}
			}
			if tc.wantOn != "" {
				// The record must name the operation and the
				// uids, which is what makes it usable.
				where := map[string]string{"stdout": stdout, "stderr": stderr, "log": string(logData)}[tc.wantOn]
				for _, field := range []string{`operation="open"`, `profile="auditprofile"`, "fsuid=", "ouid="} {
					if !strings.Contains(where, field) {
						t.Errorf("record on %s is missing %s: %q", tc.wantOn, field, where)
					}
				}
			}

			// The sandbox must still be able to die. A record
			// written to a stream nobody drains used to wedge it
			// here, with the container left unkillable.
			done := make(chan error, 1)
			go func() { done <- c.Destroy() }()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("error destroying container: %v", err)
				}
			case <-time.After(60 * time.Second):
				t.Fatal("destroying the container blocked; the sandbox is wedged")
			}
		})
	}
}

// TestAppArmorAuditFloodDoesNotWedgeSandbox covers a workload that is denied
// faster than its output is read. Records are written from the task goroutine
// while filesystem locks are held, so a record that cannot be written must be
// dropped rather than waited on: the syscall that produced it cannot finish
// until the write does.
//
// The container's stdout is a pipe this test does not read until the container
// has exited, so the denials below overflow it several times over. The workload
// must still run to completion and the sandbox must still exit.
//
// Note that the sentry sets an imported stdio pipe non-blocking itself, in
// host.NewFD(), and dup(2) shares file status flags, so a write here returns
// EWOULDBLOCK rather than waiting even without the sink asking for it. This
// test therefore proves the workload is unaffected by a flood; it does not
// prove the flags on the sink are right.
func TestAppArmorAuditFloodDoesNotWedgeSandbox(t *testing.T) {
	policyDir := setupAuditPolicy(t)
	base := filepath.Dir(policyDir)
	secret := filepath.Join(base, "secret")

	// Each denial is roughly 200 bytes and a pipe holds 64KiB by default, so
	// this is several times what the pipe can take.
	cmd := fmt.Sprintf("i=0; while [ $i -lt 800 ]; do cat %s >/dev/null 2>&1; i=$((i+1)); done; echo FINISHED", secret)
	spec := testutil.NewSpecWithArgs("sh", "-c", cmd)
	spec.Process.ApparmorProfile = "auditprofile"

	conf := testutil.TestConfig(t)
	conf.AppArmorPolicySource = "container"
	conf.AppArmorPolicyDir = policyDir
	conf.AppArmorAuditTarget = "stdout"
	conf.Debug = false
	conf.DebugLog = filepath.Join(base, "sentry.log")

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	stdio := captureStdio(t)
	defer stdio.close()

	c, err := New(conf, Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	})
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer c.Destroy()
	if err := c.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// The container must run to completion even though its output is not
	// being read.
	waited := make(chan error, 1)
	go func() {
		_, err := c.Wait()
		waited <- err
	}()
	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("error waiting on container: %v", err)
		}
	case <-time.After(120 * time.Second):
		t.Fatal("the container never finished; a record written to a full pipe blocked the task that produced it")
	}

	stdout, stderr := stdio.read(t)
	if !strings.Contains(stdout, "FINISHED") && !strings.Contains(stderr, "FINISHED") {
		t.Errorf("the workload did not run to completion; stdout=%d bytes stderr=%d bytes", len(stdout), len(stderr))
	}

	done := make(chan error, 1)
	go func() { done <- c.Destroy() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("error destroying container: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("destroying the container blocked; the sandbox is wedged")
	}
}
