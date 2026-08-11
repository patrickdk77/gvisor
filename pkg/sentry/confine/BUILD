load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "confine",
    srcs = [
        "confine.go",
        "dfa.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/errors/linuxerr",
        "//pkg/log",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
    ],
)

go_test(
    name = "confine_test",
    size = "small",
    srcs = [
        "confine_test.go",
        "dfa_test.go",
    ],
    library = ":confine",
    deps = [
        "//pkg/sync",
        "//pkg/abi/linux",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)
