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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Declared here rather than taken from <linux/openat2.h>, which is not present
// on every toolchain this test is built with.
struct open_how_t {
  uint64_t flags;
  uint64_t mode;
  uint64_t resolve;
};

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10
#define RESOLVE_CACHED 0x20
#endif

int openat2(int dirfd, const char* path, struct open_how_t* how, size_t size) {
  return syscall(SYS_openat2, dirfd, path, how, size);
}

// SkipIfUnsupported skips the test when the running kernel is older than the
// 5.6 that introduced openat2(2).
void SkipIfUnsupported() {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  int fd = openat2(AT_FDCWD, "/", &how, sizeof(how));
  if (fd < 0 && errno == ENOSYS) {
    GTEST_SKIP() << "openat2(2) is not supported by this kernel";
  }
  if (fd >= 0) {
    close(fd);
  }
}

class Openat2Test : public ::testing::Test {
 protected:
  void SetUp() override {
    SkipIfUnsupported();
    dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    file_ = ASSERT_NO_ERRNO_AND_VALUE(
        TempPath::CreateFileWith(dir_.path(), "contents", 0644));
    dirfd_ = ASSERT_NO_ERRNO_AND_VALUE(Open(dir_.path(), O_RDONLY | O_DIRECTORY));
  }

  // name returns the basename of a path under dir_.
  static std::string Base(const std::string& path) {
    return std::string(Basename(path));
  }

  TempPath dir_;
  TempPath file_;
  FileDescriptor dirfd_;
};

TEST_F(Openat2Test, Basic) {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  int fd = openat2(dirfd_.get(), Base(file_.path()).c_str(), &how, sizeof(how));
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);
}

TEST_F(Openat2Test, CreateAppliesMode) {
  struct open_how_t how = {};
  how.flags = O_RDWR | O_CREAT | O_EXCL;
  how.mode = 0640;
  const std::string name = "created";
  int fd = openat2(dirfd_.get(), name.c_str(), &how, sizeof(how));
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);

  struct stat st = {};
  ASSERT_THAT(fstatat(dirfd_.get(), name.c_str(), &st, 0), SyscallSucceeds());
  EXPECT_EQ(st.st_mode & 07777, 0640);
  ASSERT_THAT(unlinkat(dirfd_.get(), name.c_str(), 0), SyscallSucceeds());
}

// openat2(2) validates strictly where open(2) ignores what it does not
// understand. That is the point of the syscall: it is how a caller learns
// whether the restriction it asked for was actually applied.
TEST_F(Openat2Test, RejectsUnknownFlags) {
  struct open_how_t how = {};
  // A bit well above every flag Linux defines.
  how.flags = O_RDONLY | (1ULL << 40);
  EXPECT_THAT(openat2(dirfd_.get(), Base(file_.path()).c_str(), &how, sizeof(how)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(Openat2Test, RejectsUnknownResolveFlags) {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.resolve = 1ULL << 40;
  EXPECT_THAT(openat2(dirfd_.get(), Base(file_.path()).c_str(), &how, sizeof(how)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(Openat2Test, RejectsModeWithoutCreate) {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.mode = 0644;
  EXPECT_THAT(openat2(dirfd_.get(), Base(file_.path()).c_str(), &how, sizeof(how)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(Openat2Test, RejectsModeOutsidePermissionBits) {
  struct open_how_t how = {};
  how.flags = O_RDWR | O_CREAT;
  how.mode = 010000;  // Above 07777.
  EXPECT_THAT(openat2(dirfd_.get(), "created", &how, sizeof(how)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(Openat2Test, RejectsShortStruct) {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  EXPECT_THAT(openat2(dirfd_.get(), Base(file_.path()).c_str(), &how,
                      sizeof(how) - 1),
              SyscallFailsWithErrno(EINVAL));
}

// A larger structure is an extension this kernel does not know. It is
// tolerated only if the caller left it zeroed, meaning it is not asking for
// anything; a non-zero extension cannot be honoured as written.
TEST_F(Openat2Test, LargerStructZeroed) {
  struct extended_t {
    struct open_how_t how;
    uint64_t future;
  } ext = {};
  ext.how.flags = O_RDONLY;
  int fd = openat2(dirfd_.get(), Base(file_.path()).c_str(), &ext.how,
                   sizeof(ext));
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);
}

TEST_F(Openat2Test, LargerStructNonZero) {
  struct extended_t {
    struct open_how_t how;
    uint64_t future;
  } ext = {};
  ext.how.flags = O_RDONLY;
  ext.future = 1;
  EXPECT_THAT(openat2(dirfd_.get(), Base(file_.path()).c_str(), &ext.how,
                      sizeof(ext)),
              SyscallFailsWithErrno(E2BIG));
}

TEST_F(Openat2Test, NoSymlinksRejectsSymlink) {
  const std::string link = JoinPath(dir_.path(), "link");
  ASSERT_THAT(symlink(Base(file_.path()).c_str(), link.c_str()),
              SyscallSucceeds());

  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.resolve = RESOLVE_NO_SYMLINKS;
  EXPECT_THAT(openat2(dirfd_.get(), "link", &how, sizeof(how)),
              SyscallFailsWithErrno(ELOOP));

  // The same open without the restriction succeeds, so the failure above is
  // the restriction and not a broken link.
  how.resolve = 0;
  int fd = openat2(dirfd_.get(), "link", &how, sizeof(how));
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);
  ASSERT_THAT(unlink(link.c_str()), SyscallSucceeds());
}

// With O_NOFOLLOW the final component is not resolved, so RESOLVE_NO_SYMLINKS
// still allows an O_PATH descriptor for the link itself.
TEST_F(Openat2Test, NoSymlinksAllowsOPathNoFollow) {
  const std::string link = JoinPath(dir_.path(), "link");
  ASSERT_THAT(symlink(Base(file_.path()).c_str(), link.c_str()),
              SyscallSucceeds());

  struct open_how_t how = {};
  how.flags = O_PATH | O_NOFOLLOW;
  how.resolve = RESOLVE_NO_SYMLINKS;
  int fd = openat2(dirfd_.get(), "link", &how, sizeof(how));
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);
  ASSERT_THAT(unlink(link.c_str()), SyscallSucceeds());
}

TEST_F(Openat2Test, NoSymlinksRejectsSymlinkInMiddle) {
  const std::string sub = JoinPath(dir_.path(), "sub");
  ASSERT_THAT(mkdir(sub.c_str(), 0755), SyscallSucceeds());
  const std::string link = JoinPath(dir_.path(), "dirlink");
  ASSERT_THAT(symlink("sub", link.c_str()), SyscallSucceeds());
  const std::string target = JoinPath(sub, "f");
  int fd = open(target.c_str(), O_RDWR | O_CREAT, 0644);
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);

  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.resolve = RESOLVE_NO_SYMLINKS;
  EXPECT_THAT(openat2(dirfd_.get(), "dirlink/f", &how, sizeof(how)),
              SyscallFailsWithErrno(ELOOP));

  ASSERT_THAT(unlink(target.c_str()), SyscallSucceeds());
  ASSERT_THAT(unlink(link.c_str()), SyscallSucceeds());
  ASSERT_THAT(rmdir(sub.c_str()), SyscallSucceeds());
}

TEST_F(Openat2Test, BeneathAllowsPathInside) {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.resolve = RESOLVE_BENEATH;
  int fd = openat2(dirfd_.get(), Base(file_.path()).c_str(), &how, sizeof(how));
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);
}

TEST_F(Openat2Test, BeneathRejectsDotDot) {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.resolve = RESOLVE_BENEATH;
  EXPECT_THAT(openat2(dirfd_.get(), "..", &how, sizeof(how)),
              SyscallFailsWithErrno(EXDEV));
}

TEST_F(Openat2Test, BeneathRejectsAbsolutePath) {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.resolve = RESOLVE_BENEATH;
  EXPECT_THAT(openat2(dirfd_.get(), "/etc/hosts", &how, sizeof(how)),
              SyscallFailsWithErrno(EXDEV));
}

TEST_F(Openat2Test, BeneathRejectsAbsoluteSymlink) {
  const std::string link = JoinPath(dir_.path(), "abs");
  ASSERT_THAT(symlink("/etc/hosts", link.c_str()), SyscallSucceeds());

  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.resolve = RESOLVE_BENEATH;
  EXPECT_THAT(openat2(dirfd_.get(), "abs", &how, sizeof(how)),
              SyscallFailsWithErrno(EXDEV));
  ASSERT_THAT(unlink(link.c_str()), SyscallSucceeds());
}

// RESOLVE_IN_ROOT clamps rather than refusing: dirfd becomes "/", so ".." at
// the top stays put and an absolute path is resolved inside it.
TEST_F(Openat2Test, InRootClampsDotDot) {
  struct open_how_t how = {};
  how.flags = O_RDONLY | O_DIRECTORY;
  how.resolve = RESOLVE_IN_ROOT;
  int fd = openat2(dirfd_.get(), "../../..", &how, sizeof(how));
  ASSERT_THAT(fd, SyscallSucceeds());

  // What was opened is dirfd itself, not the real root.
  struct stat got = {};
  struct stat want = {};
  ASSERT_THAT(fstat(fd, &got), SyscallSucceeds());
  ASSERT_THAT(fstat(dirfd_.get(), &want), SyscallSucceeds());
  EXPECT_EQ(got.st_ino, want.st_ino);
  EXPECT_EQ(got.st_dev, want.st_dev);
  close(fd);
}

TEST_F(Openat2Test, InRootResolvesAbsolutePathInsideDir) {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.resolve = RESOLVE_IN_ROOT;
  // Absolute, so it names the file inside dirfd rather than on the real root.
  const std::string abs = "/" + Base(file_.path());
  int fd = openat2(dirfd_.get(), abs.c_str(), &how, sizeof(how));
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);
}

TEST_F(Openat2Test, InRootResolvesAbsoluteSymlinkInsideDir) {
  // An absolute symlink is resolved from dirfd, so this points at the file in
  // dir_ rather than at a path on the real root.
  const std::string link = JoinPath(dir_.path(), "abs");
  ASSERT_THAT(symlink(("/" + Base(file_.path())).c_str(), link.c_str()),
              SyscallSucceeds());

  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.resolve = RESOLVE_IN_ROOT;
  int fd = openat2(dirfd_.get(), "abs", &how, sizeof(how));
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);
  ASSERT_THAT(unlink(link.c_str()), SyscallSucceeds());
}

// RESOLVE_CACHED asks for a resolution that does no I/O. A kernel is always
// free to answer EAGAIN, and the caller must retry without the flag, so this
// asserts the contract rather than a particular outcome.
TEST_F(Openat2Test, CachedSucceedsOrEagain) {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  how.resolve = RESOLVE_CACHED;
  int fd = openat2(dirfd_.get(), Base(file_.path()).c_str(), &how, sizeof(how));
  if (fd < 0) {
    EXPECT_EQ(errno, EAGAIN);
  } else {
    close(fd);
  }
}

TEST_F(Openat2Test, EmptyPathIsENOENT) {
  struct open_how_t how = {};
  how.flags = O_RDONLY;
  EXPECT_THAT(openat2(dirfd_.get(), "", &how, sizeof(how)),
              SyscallFailsWithErrno(ENOENT));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
