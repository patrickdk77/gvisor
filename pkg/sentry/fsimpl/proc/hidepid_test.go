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

package proc

import (
	"testing"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

func TestParseHidePid(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    HidePidMode
		wantErr bool
	}{
		{in: "0", want: HidePidOff},
		{in: "off", want: HidePidOff},
		{in: "1", want: HidePidNoAccess},
		{in: "noaccess", want: HidePidNoAccess},
		{in: "2", want: HidePidInvisible},
		{in: "invisible", want: HidePidInvisible},
		{in: "3", wantErr: true},
		{in: "", wantErr: true},
		{in: "yes", wantErr: true},
	} {
		got, err := parseHidePid(tc.in)
		if tc.wantErr {
			if !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Errorf("parseHidePid(%q) error = %v, want EINVAL", tc.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseHidePid(%q) = %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseHidePid(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
