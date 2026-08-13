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

package kernel

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/confine"
)

// init installs the resolver for the "pid" and "comm" fields of an AppArmor
// audit record. It lives here because those fields belong to a task, and the
// confine package cannot import this one, which imports it.
func init() {
	confine.SetTaskInfoFunc(func(ctx context.Context) (int32, string, bool) {
		t := TaskFromContext(ctx)
		if t == nil {
			return 0, "", false
		}
		// Linux's dump_common_audit_data() prints task_tgid_nr(current) as
		// pid, which is the thread group ID in the root namespace, and
		// current->comm, which is the thread's own name.
		tg := t.ThreadGroup()
		if tg == nil {
			return 0, "", false
		}
		pid := tg.PIDNamespace().Root().IDOfThreadGroup(tg)
		return int32(pid), t.Name(), true
	})
}
