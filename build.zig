const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ocispec_dep = b.dependency("ocispec", .{});
    const ocispec_module = ocispec_dep.module("ocispec");

    const runz_module = b.addModule("runz", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ocispec", .module = ocispec_module },
        },
    });

    // CLI binary
    const exe = b.addExecutable(.{
        .name = "runz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "runz", .module = runz_module },
            },
        }),
    });
    b.installArtifact(exe);

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

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    // Layer 1: Library integration tests
    const integration_module = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    integration_module.addImport("runz", runz_module);
    const integration_tests = b.addTest(.{
        .root_module = integration_module,
    });
    const integration_step = b.step("test-integration", "Run library integration tests");
    integration_step.dependOn(&b.addRunArtifact(integration_tests).step);

    // Layer 2: CLI end-to-end tests (requires built binary)
    const cli_module = b.createModule(.{
        .root_source_file = b.path("tests/cli.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const cli_tests = b.addTest(.{
        .root_module = cli_module,
    });
    const cli_step = b.step("test-cli", "Run CLI end-to-end tests (requires built binary)");
    cli_step.dependOn(b.getInstallStep()); // ensure binary is built first
    cli_step.dependOn(&b.addRunArtifact(cli_tests).step);

    // Layer 3: upstream OCI runtime-tools validation suite.
    // Runs the same conformance tests that runc/crun/youki use. Requires
    // root and the env vars OCI_VALIDATION_DIR / OCI_RUNTIMETEST, which
    // `nix develop` exports from the oci-runtime-tools derivation in
    // flake.nix. The wrapper script skips cleanly when those aren't set.
    const oci_validation_step = b.step("test-oci-validation", "Run upstream OCI runtime-tools validation (requires root + nix devShell)");
    oci_validation_step.dependOn(b.getInstallStep());
    const oci_validation_run = b.addSystemCommand(&.{
        "bash",
        "scripts/oci-validation.sh",
    });
    oci_validation_run.setEnvironmentVariable(
        "RUNTIME",
        b.getInstallPath(.bin, "runz"),
    );
    oci_validation_step.dependOn(&oci_validation_run.step);

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

    // Docs step
    const docs_step = b.step("docs", "Generate API documentation");

    const docs_lib = b.addLibrary(.{
        .name = "runz",
        .root_module = runz_module,
    });

    const docs_install = b.addInstallDirectory(.{
        .source_dir = docs_lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    docs_step.dependOn(&docs_install.step);
}
