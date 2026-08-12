// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"errors"
	"testing"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
)

func TestContainerUpdateNilResources(t *testing.T) {
	c := &Container{}
	err := c.Update(t.Context(), &task.UpdateTaskRequest{ID: "x", Resources: nil})
	if !errors.Is(err, errdefs.ErrInvalidArgument) {
		t.Fatalf("Update(nil Resources): %v, want ErrInvalidArgument", err)
	}
}

func TestCgroupPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{
			name: "simple",
			path: "foo/pod123/container",
			want: "foo/pod123",
		},
		{
			name: "absolute",
			path: "/foo/pod123/container",
			want: "/foo/pod123",
		},
		{
			name: "no-container",
			path: "foo/pod123",
			want: "",
		},
		{
			name: "no-container-absolute",
			path: "/foo/pod123",
			want: "",
		},
		{
			name: "double-pod",
			path: "/foo/podium/pod123/container",
			want: "/foo/podium/pod123",
		},
		{
			name: "start-pod",
			path: "pod123/container",
			want: "pod123",
		},
		{
			name: "start-pod-absolute",
			path: "/pod123/container",
			want: "/pod123",
		},
		{
			name: "slashes",
			path: "///foo/////pod123//////container",
			want: "/foo/pod123",
		},
		{
			name: "no-pod",
			path: "/foo/nopod123/container",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := specs.Spec{
				Linux: &specs.Linux{
					CgroupsPath: tc.path,
				},
			}
			updated := setPodCgroup(&spec)
			if got := spec.Annotations[cgroupParentAnnotation]; got != tc.want {
				t.Errorf("setPodCgroup(%q), want: %q, got: %q", tc.path, tc.want, got)
			}
			if shouldUpdate := len(tc.want) > 0; shouldUpdate != updated {
				t.Errorf("setPodCgroup(%q)=%v, want: %v", tc.path, updated, shouldUpdate)
			}
		})
	}
}

// Test cases that cgroup path should not be updated.
func TestCgroupNoUpdate(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *specs.Spec
	}{
		{
			name: "empty",
			spec: &specs.Spec{},
		},
		{
			name: "subcontainer",
			spec: &specs.Spec{
				Linux: &specs.Linux{
					CgroupsPath: "foo/pod123/container",
				},
				Annotations: map[string]string{
					utils.ContainerTypeAnnotation: utils.ContainerTypeContainer,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if updated := setPodCgroup(tc.spec); updated {
				t.Errorf("setPodCgroup(%+v), got: %v, want: false", tc.spec.Linux, updated)
			}
		})
	}
}

func TestSetPodResources(t *testing.T) {
	i64p := func(v int64) *int64 { return &v }
	u64p := func(v uint64) *uint64 { return &v }
	defaultAnnotations := map[string]string{
		sandboxCPUPeriodAnnotation: "100000",
		sandboxCPUQuotaAnnotation:  "85800",
		sandboxCPUSharesAnnotation: "684",
		sandboxMemoryAnnotation:    "2304770048",
	}
	for _, tc := range []struct {
		name        string
		spec        *specs.Spec
		wantUpdated bool
		wantQuota   *int64
		wantPeriod  *uint64
		wantShares  *uint64
		wantMemory  *int64
	}{
		{
			name: "full",
			spec: &specs.Spec{
				Linux: &specs.Linux{
					Resources: &specs.LinuxResources{
						CPU: &specs.LinuxCPU{Shares: u64p(2)},
					},
				},
				Annotations: defaultAnnotations,
			},
			wantUpdated: true,
			wantQuota:   i64p(85800),
			wantPeriod:  u64p(100000),
			wantShares:  u64p(684),
			wantMemory:  i64p(2304770048),
		},
		{
			name: "not-sandbox",
			spec: &specs.Spec{
				Linux: &specs.Linux{},
				Annotations: map[string]string{
					utils.ContainerTypeAnnotation: utils.ContainerTypeContainer,
					sandboxCPUQuotaAnnotation:     "85800",
					sandboxCPUPeriodAnnotation:    "100000",
				},
			},
			wantUpdated: false,
		},
		{
			name: "nil-linux",
			spec: &specs.Spec{
				Annotations: defaultAnnotations,
			},
			wantUpdated: false,
		},
		{
			name: "no-annotations",
			spec: &specs.Spec{
				Linux: &specs.Linux{},
			},
			wantUpdated: false,
		},
		{
			name: "malformed-quota-good-memory",
			spec: &specs.Spec{
				Linux: &specs.Linux{},
				Annotations: map[string]string{
					sandboxCPUQuotaAnnotation:  "not-a-number",
					sandboxCPUPeriodAnnotation: "100000",
					sandboxMemoryAnnotation:    "1048576",
				},
			},
			wantUpdated: true,
			wantMemory:  i64p(1048576),
		},
		{
			name: "zero-quota-unlimited",
			spec: &specs.Spec{
				Linux: &specs.Linux{},
				Annotations: map[string]string{
					sandboxCPUQuotaAnnotation:  "0",
					sandboxCPUPeriodAnnotation: "100000",
				},
			},
			wantUpdated: false,
		},
		{
			name: "negative-memory-ignored",
			spec: &specs.Spec{
				Linux: &specs.Linux{},
				Annotations: map[string]string{
					sandboxMemoryAnnotation: "-5",
				},
			},
			wantUpdated: false,
		},
		{
			name: "existing-quota-preserved",
			spec: &specs.Spec{
				Linux: &specs.Linux{
					Resources: &specs.LinuxResources{
						CPU: &specs.LinuxCPU{
							Quota:  i64p(50000),
							Period: u64p(100000),
							Shares: u64p(512),
						},
					},
				},
				Annotations: map[string]string{
					sandboxCPUQuotaAnnotation:  "85800",
					sandboxCPUPeriodAnnotation: "100000",
					sandboxCPUSharesAnnotation: "684",
				},
			},
			wantUpdated: false,
			wantQuota:   i64p(50000),
			wantPeriod:  u64p(100000),
			wantShares:  u64p(512),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			updated := setPodResources(tc.spec)
			if updated != tc.wantUpdated {
				t.Errorf("setPodResources() = %v, want %v", updated, tc.wantUpdated)
			}
			var cpu *specs.LinuxCPU
			var memory *specs.LinuxMemory
			if tc.spec.Linux != nil && tc.spec.Linux.Resources != nil {
				cpu = tc.spec.Linux.Resources.CPU
				memory = tc.spec.Linux.Resources.Memory
			}
			checkI64 := func(field string, got, want *int64) {
				if (got == nil) != (want == nil) {
					t.Errorf("%s: got %v, want %v", field, got, want)
				} else if got != nil && *got != *want {
					t.Errorf("%s: got %d, want %d", field, *got, *want)
				}
			}
			checkU64 := func(field string, got, want *uint64) {
				if (got == nil) != (want == nil) {
					t.Errorf("%s: got %v, want %v", field, got, want)
				} else if got != nil && *got != *want {
					t.Errorf("%s: got %d, want %d", field, *got, *want)
				}
			}
			var gotQuota *int64
			var gotPeriod, gotShares *uint64
			if cpu != nil {
				gotQuota, gotPeriod = cpu.Quota, cpu.Period
				gotShares = cpu.Shares
			}
			var gotMemory *int64
			if memory != nil {
				gotMemory = memory.Limit
			}
			checkI64("cpu.quota", gotQuota, tc.wantQuota)
			checkU64("cpu.period", gotPeriod, tc.wantPeriod)
			checkU64("cpu.shares", gotShares, tc.wantShares)
			checkI64("memory.limit", gotMemory, tc.wantMemory)
		})
	}
}
