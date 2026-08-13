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

package boot

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/confine"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// TestBehaviorMatchesRealKernel replays decisions captured from a live kernel
// against the parser and the engine together: the profiles the kernel enforced
// are parsed from testdata exactly as they were loaded there, and every probe
// in testdata/apparmor_behavior.tsv must produce the same outcome and the same
// record, byte for byte, or none where the kernel logged none.
//
// The AARE corpus verifies what a pattern matches and the audit corpus
// verifies how a record is written; this one verifies the decisions between
// them, across opens, appends, mmap, links, exec transitions, change_profile,
// complain mode and kill mode. Its capture has already caught real
// divergences: exec is mediated as "x" alone rather than as an open for "rx",
// a ux transition is silent, and an immediate change_profile denial names the
// target profile with no masks.
func TestBehaviorMatchesRealKernel(t *testing.T) {
	policy := &AppArmorPolicy{}
	tun := make(tunables)
	for _, fname := range []string{"testdata/gvisor_behav.aa", "testdata/gvisor_behav2.aa"} {
		text, err := os.ReadFile(fname)
		if err != nil {
			t.Fatalf("reading %s: %v", fname, err)
		}
		if err := ParseAppArmorProfiles(strings.NewReader(string(text)), fname, policy, tun); err != nil {
			t.Fatalf("parsing %s: %v", fname, err)
		}
	}
	confine.SetPolicy(policy.Rules)
	defer confine.SetPolicy(nil)
	auth.SetExecConfinementProfiles(policy.ExecAttach)
	defer auth.SetExecConfinementProfiles(nil)

	var logged []string
	confine.SetTestLogSink(func(record string) { logged = append(logged, record) })
	defer confine.SetTestLogSink(nil)
	defer confine.SetTaskInfoFunc(nil)

	data, err := os.ReadFile("testdata/apparmor_behavior.tsv")
	if err != nil {
		t.Fatalf("reading the captured decisions: %v", err)
	}
	ctx := context.Background()
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 9 {
			t.Fatalf("malformed line (%d fields): %q", len(f), line)
		}
		kind, profile, arg1, arg2, ouidStr, want, pidStr, comm, record :=
			f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]
		label := kind + " " + arg1
		ouid, err := strconv.Atoi(ouidStr)
		if err != nil {
			t.Fatalf("%s: bad ouid %q: %v", label, ouidStr, err)
		}
		if record != "-" {
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				t.Fatalf("%s: bad pid %q: %v", label, pidStr, err)
			}
			confine.SetTaskInfoFunc(func(context.Context) (int32, string, bool) {
				return int32(pid), comm, true
			})
		} else {
			confine.SetTaskInfoFunc(nil)
		}

		creds := auth.NewAnonymousCredentials()
		creds.EffectiveKUID = auth.KUID(1000)
		if profile == "-" {
			// The probe ran unconfined; attachment decides the profile.
			profile = ""
		}
		creds.ConfinementProfile = profile

		mode := linux.FileMode(0666)
		if strings.HasSuffix(arg1, "/") {
			mode = linux.ModeDirectory | 0755
		}

		logged = nil
		var gotErr error
		var gotProfile string
		switch kind {
		case "open", "openappend":
			var ats vfs.AccessTypes
			var flags uint32
			switch arg2 {
			case "r":
				ats = vfs.MayRead
			case "w":
				ats = vfs.MayWrite
			case "a":
				ats = vfs.MayWrite
				flags = unix.O_APPEND
			default:
				t.Fatalf("%s: bad access %q", label, arg2)
			}
			gotErr = confine.CheckOpen(ctx, creds, arg1, ats, flags, mode, auth.KUID(ouid))
		case "mmap":
			gotErr = confine.CheckPerms(ctx, creds, confine.OpFmmap, arg1, confine.ParsePerms("m"), mode, auth.KUID(ouid))
		case "link":
			gotErr = confine.CheckLink(ctx, creds, arg1, arg2, mode, auth.KUID(ouid))
		case "exec":
			// An exec is mediated in two steps, as the sandbox does it:
			// the open-for-exec asks for "x" on the file, then the
			// transition decides the landing profile.
			if profile != "" {
				gotErr = confine.CheckPerms(ctx, creds, confine.OpExec, arg1, confine.Exec, mode, auth.KUID(ouid))
			}
			if gotErr == nil {
				newProfile, _, terr := confine.TransitionOnExec(ctx, profile, arg1)
				gotErr = terr
				if newProfile == "" {
					gotProfile = "unconfined"
				} else {
					gotProfile = newProfile
				}
			}
		case "chprof":
			gotErr = confine.CheckChangeProfile(ctx, profile, arg1)
		default:
			t.Fatalf("%s: unknown kind", label)
		}

		switch want {
		case "0":
			if gotErr != nil {
				t.Errorf("%s: the kernel allowed this, the engine denied it: %v", label, gotErr)
			}
		case "EACCES":
			if gotErr == nil {
				t.Errorf("%s: the kernel denied this, the engine allowed it", label)
			}
		case "KILL":
			if _, kill := confine.AsKillError(gotErr); !kill {
				t.Errorf("%s: the kernel SIGKILLed this, the engine returned %v", label, gotErr)
			}
		default:
			// An exec landing profile.
			if gotErr != nil {
				t.Errorf("%s: the kernel ran this in %q, the engine denied it: %v", label, want, gotErr)
			} else if gotProfile != want {
				t.Errorf("%s: the kernel ran this in %q, the engine in %q", label, want, gotProfile)
			}
		}
		if record == "-" {
			if len(logged) != 0 {
				t.Errorf("%s: the kernel logged nothing, the engine logged: %v", label, logged)
			}
		} else {
			if len(logged) != 1 {
				t.Errorf("%s: logged %d records, want the kernel's one: %v", label, len(logged), logged)
			} else if logged[0] != record {
				t.Errorf("%s: record differs from the kernel's:\n got  %s\n want %s", label, logged[0], record)
			}
		}
		n++
	}
	if n == 0 {
		t.Fatal("the captured decisions are empty")
	}
}
