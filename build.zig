const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ocispec_dep = b.dependency("ocispec", .{});
    const ocispec_module = ocispec_dep.module("ocispec");

    const oci_module = b.addModule("oci", .{
        .root_source_file = b.path("src/lib.zig"),
        .imports = &.{
            .{ .name = "ocispec", .module = ocispec_module },
        },
    });
    _ = oci_module;

    // Tests
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_module.addImport("ocispec", ocispec_module);
    const tests = b.addTest(.{
        .root_module = test_module,
    });

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    // Fuzz targets
    const fuzz_module = b.createModule(.{
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    fuzz_module.addImport("ocispec", ocispec_module);
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_module,
    });

    const fuzz_step = b.step("fuzz", "Run fuzz tests (use -ffuzz to enable fuzzing mode)");
    fuzz_step.dependOn(&b.addRunArtifact(fuzz_tests).step);

    // Valgrind step: run tests under valgrind
    const valgrind_step = b.step("valgrind", "Run tests under valgrind");
    const valgrind_run = b.addSystemCommand(&.{
        "valgrind",
        "--leak-check=full",
        "--error-exitcode=1",
        "--track-origins=yes",
        "--suppressions=/dev/null",
    });
    valgrind_run.addArtifactArg(tests);
    valgrind_step.dependOn(&valgrind_run.step);
}
