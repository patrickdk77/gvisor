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

#include <sys/mount.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr char kTmpfs[] = "tmpfs";

// These tests exist because generating /proc/[pid]/mountinfo is expensive
// enough to be worth reusing a previous copy, and reuse is only safe if every
// change to what it reports is noticed. Each test below performs one kind of
// change and asserts that the contents change with it, so that a missed
// invalidation fails here rather than silently feeding stale mount state to
// whatever parses this file, which for container tooling is everything.
std::string MountInfo() {
  auto contents = GetContents("/proc/self/mountinfo");
  if (!contents.ok()) {
    return "";
  }
  return contents.ValueOrDie();
}

// LineFor returns the mountinfo line whose mount point is path, or "".
std::string LineFor(const std::string& contents, const std::string& path) {
  size_t pos = 0;
  while (pos < contents.size()) {
    size_t end = contents.find('\n', pos);
    if (end == std::string::npos) {
      end = contents.size();
    }
    const std::string line = contents.substr(pos, end - pos);
    // Field 5 is the mount point, surrounded by spaces.
    if (line.find(" " + path + " ") != std::string::npos) {
      return line;
    }
    pos = end + 1;
  }
  return "";
}

TEST(MountInfoTest, MountAndUnmountAreVisible) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_EQ(LineFor(MountInfo(), dir.path()), "")
      << "the mount point is listed before anything is mounted on it";
  {
    auto mnt =
        ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), kTmpfs, 0, "", 0));
    EXPECT_NE(LineFor(MountInfo(), dir.path()), "")
        << "a new mount is missing from mountinfo";
  }
  // The Cleanup unmounted it.
  EXPECT_EQ(LineFor(MountInfo(), dir.path()), "")
      << "an unmounted mount is still listed in mountinfo";
}

TEST(MountInfoTest, RemountReadOnlyIsVisible) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mnt = ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), kTmpfs, 0, "", 0));

  const std::string before = LineFor(MountInfo(), dir.path());
  ASSERT_NE(before, "");
  EXPECT_NE(before.find(" rw"), std::string::npos) << before;

  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_REMOUNT | MS_RDONLY, ""),
              SyscallSucceeds());
  const std::string after = LineFor(MountInfo(), dir.path());
  ASSERT_NE(after, "");
  EXPECT_NE(after.find(" ro"), std::string::npos)
      << "a remount to read-only is not reflected in mountinfo: " << after;
}

TEST(MountInfoTest, PropagationChangeIsVisible) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mnt = ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), kTmpfs, 0, "", 0));

  const std::string before = LineFor(MountInfo(), dir.path());
  ASSERT_NE(before, "");

  // Making the mount shared adds a "shared:N" optional field, which is a
  // change to the file that involves no mount or unmount.
  ASSERT_THAT(mount("", dir.path().c_str(), "", MS_SHARED, ""),
              SyscallSucceeds());
  const std::string after = LineFor(MountInfo(), dir.path());
  ASSERT_NE(after, "");
  EXPECT_NE(after.find("shared:"), std::string::npos)
      << "a propagation change is not reflected in mountinfo: " << after;
}

TEST(MountInfoTest, RenameAboveMountPointIsVisible) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  auto parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string outer = JoinPath(parent.path(), "outer");
  const std::string inner = JoinPath(outer, "inner");
  ASSERT_THAT(mkdir(outer.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(inner.c_str(), 0755), SyscallSucceeds());
  auto mnt = ASSERT_NO_ERRNO_AND_VALUE(Mount("", inner, kTmpfs, 0, "", 0));

  ASSERT_NE(LineFor(MountInfo(), inner), "");

  // Renaming a directory above the mount point changes the pathname mountinfo
  // reports for it, with no mount operation involved. This is the case a cache
  // keyed only on mount changes would get wrong.
  const std::string renamed = JoinPath(parent.path(), "renamed");
  int rc = rename(outer.c_str(), renamed.c_str());
  if (rc != 0) {
    // Some kernels refuse to rename a directory containing a mount point. If
    // so, there is nothing to observe here.
    EXPECT_THAT(rc, SyscallFailsWithErrno(EBUSY));
    GTEST_SKIP() << "renaming a directory above a mount point is not permitted";
  }
  // The mount moved with the rename, so the automatic unmount would target a
  // path that no longer exists. Unmount it by hand below instead.
  mnt.Release();

  const std::string moved = JoinPath(renamed, "inner");
  EXPECT_NE(LineFor(MountInfo(), moved), "")
      << "after renaming a directory above a mount point, mountinfo still "
         "reports the old pathname";
  EXPECT_EQ(LineFor(MountInfo(), inner), "")
      << "mountinfo reports the pre-rename pathname for a mount";

  EXPECT_THAT(umount2(moved.c_str(), 0), SyscallSucceeds());
  // Put the directory back so that the temporary path can be cleaned up.
  EXPECT_THAT(rename(renamed.c_str(), outer.c_str()), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
