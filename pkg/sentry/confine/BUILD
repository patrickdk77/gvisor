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
        "//pkg/context",
        "//pkg/errors",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "confine_test",
    size = "medium",
    srcs = [
        "confine_test.go",
        "stress_test.go",
        "wildcard_bench_test.go",
        "bench_test.go",
        "dfa_test.go",
        "reference_test.go",
    ],
    data = [
        "testdata/aare_reference.tsv",
        "testdata/audit_reference.tsv",
    ],
    library = ":confine",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
