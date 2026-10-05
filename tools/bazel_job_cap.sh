#!/bin/bash

# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Mounted over `bazel` in the build container by tools/bazel.mk. Commands that
# execute actions never run more than MAX_JOBS actions or tests at once: any
# parallelism flag on the command line is dropped and the cap is appended last,
# where it overrides rc files and --config expansions too.

set -euo pipefail

readonly REAL_BAZEL=/usr/local/bin/bazel
readonly MAX_JOBS=4
readonly CAP=(
  "--jobs=${MAX_JOBS}"
  "--local_test_jobs=${MAX_JOBS}"
  "--local_resources=cpu=${MAX_JOBS}"
)

args=("$@")
verb_index=-1
for i in "${!args[@]}"; do
  case "${args[$i]}" in
    build | test | run | coverage)
      verb_index="${i}"
      break
      ;;
    analyze-profile | aquery | canonicalize-flags | clean | cquery | dump | \
      fetch | help | info | license | mobile-install | mod | print_action | \
      query | shutdown | sync | vendor | version)
      break
      ;;
  esac
done
if [[ "${verb_index}" -lt 0 ]]; then
  exec "${REAL_BAZEL}" "$@"
fi

out=("${args[@]:0:verb_index+1}")
tail=()
dropped=()
skip_next=false
for ((i = verb_index + 1; i < ${#args[@]}; i++)); do
  a="${args[$i]}"
  if "${skip_next}"; then
    dropped+=("${a}")
    skip_next=false
    continue
  fi
  case "${a}" in
    --)
      tail=("${args[@]:i}")
      break
      ;;
    --jobs | -j | --local_test_jobs | --local_cpu_resources)
      dropped+=("${a}")
      skip_next=true
      ;;
    --jobs=* | -j?* | --local_test_jobs=* | --local_cpu_resources=* | \
      --local_resources=cpu=*)
      dropped+=("${a}")
      ;;
    --local_resources)
      if [[ "${args[$((i + 1))]:-}" == cpu=* ]]; then
        dropped+=("${a}")
        skip_next=true
      else
        out+=("${a}")
      fi
      ;;
    *)
      out+=("${a}")
      ;;
  esac
done
if [[ "${#dropped[@]}" -gt 0 ]]; then
  echo "bazel_job_cap.sh: dropped ${dropped[*]}; running with ${CAP[*]}" >&2
fi
exec "${REAL_BAZEL}" "${out[@]}" "${CAP[@]}" "${tail[@]}"
