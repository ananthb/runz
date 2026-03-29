const std = @import("std");
const helpers = @import("helpers.zig");

// ============================================================================
// Layer 2: CLI end-to-end tests
// These invoke the runz binary as a subprocess, exactly how podman/containerd
// would use it. Tests the OCI runtime interface contract.
// ============================================================================

const runz_bin = "zig-out/bin/runz";

fn run(allocator: std.mem.Allocator, argv: []const []const u8) !struct { stdout: []const u8, stderr: []const u8, exit_code: u8 } {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.spawn() catch return error.SpawnFailed;

    var stdout_buf: [65536]u8 = undefined;
    var stderr_buf: [65536]u8 = undefined;
    const stdout_n = child.stdout.?.readAll(&stdout_buf) catch 0;
    const stderr_n = child.stderr.?.readAll(&stderr_buf) catch 0;

    const result = child.wait() catch return error.WaitFailed;
    return .{
        .stdout = try allocator.dupe(u8, stdout_buf[0..stdout_n]),
        .stderr = try allocator.dupe(u8, stderr_buf[0..stderr_n]),
        .exit_code = result.Exited,
    };
}

// --- Version and help ---

test "cli: runz --version" {
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ runz_bin, "--version" });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "runz version") != null);
}

test "cli: runz --help" {
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ runz_bin, "--help" });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
    // Help goes to stderr
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "create") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "start") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "kill") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "delete") != null);
}

// --- spec command ---

test "cli: runz spec outputs valid JSON" {
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ runz_bin, "spec" });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.exit_code);

    // Verify it's valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    // Verify required OCI fields
    try std.testing.expect(parsed.value.object.get("ociVersion") != null);
    try std.testing.expect(parsed.value.object.get("process") != null);
    try std.testing.expect(parsed.value.object.get("root") != null);
    try std.testing.expect(parsed.value.object.get("linux") != null);

    // Verify ociVersion
    const version = parsed.value.object.get("ociVersion").?;
    try std.testing.expectEqualStrings("1.0.2", version.string);
}

// --- Error handling ---

test "cli: runz create without id fails" {
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ runz_bin, "create" });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.exit_code != 0);
}

test "cli: runz start without id fails" {
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ runz_bin, "start" });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.exit_code != 0);
}

test "cli: runz state of nonexistent container fails" {
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ runz_bin, "state", "nonexistent-container-xyz" });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.exit_code != 0);
}

test "cli: runz kill without id fails" {
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ runz_bin, "kill" });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.exit_code != 0);
}

test "cli: unknown command fails" {
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ runz_bin, "foobar" });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expect(result.exit_code != 0);
}

// --- list on empty state ---

test "cli: runz list with custom root" {
    const allocator = std.testing.allocator;

    const ts1: u64 = @intCast(std.time.timestamp());
    const state_dir = try std.fmt.allocPrint(allocator, "/tmp/runz-clitest-{x}", .{ts1});
    defer allocator.free(state_dir);
    std.fs.makeDirAbsolute(state_dir) catch return;
    defer std.fs.deleteTreeAbsolute(state_dir) catch {};

    const result = try run(allocator, &.{ runz_bin, "--root", state_dir, "list" });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
    // Should have header
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "ID") != null);
}

// --- Full lifecycle (create → state → delete) ---
// Note: create/start FIFO split is not yet wired up, so this tests
// the state management path only.

test "cli: create and delete lifecycle" {
    // create now forks container processes which requires root
    if (std.os.linux.getuid() != 0) return;

    const allocator = std.testing.allocator;

    const ts2: u64 = @intCast(std.time.timestamp());
    const state_dir = try std.fmt.allocPrint(allocator, "/tmp/runz-lifecycle-{x}", .{ts2});
    defer allocator.free(state_dir);
    std.fs.makeDirAbsolute(state_dir) catch return;
    defer std.fs.deleteTreeAbsolute(state_dir) catch {};

    // Create a bundle
    const config = try helpers.minimalConfig(allocator, &.{"/bin/true"});
    defer allocator.free(config);
    const bundle = try helpers.createTestBundle(allocator, config);
    defer {
        helpers.cleanupBundle(bundle);
        allocator.free(bundle);
    }

    // Create container
    const create_result = try run(allocator, &.{
        runz_bin, "--root", state_dir, "create", "test-lifecycle", "-b", bundle,
    });
    defer allocator.free(create_result.stdout);
    defer allocator.free(create_result.stderr);
    try std.testing.expectEqual(@as(u8, 0), create_result.exit_code);

    // State should show "created"
    const state_result = try run(allocator, &.{
        runz_bin, "--root", state_dir, "state", "test-lifecycle",
    });
    defer allocator.free(state_result.stdout);
    defer allocator.free(state_result.stderr);
    try std.testing.expectEqual(@as(u8, 0), state_result.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, state_result.stdout, "created") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_result.stdout, "test-lifecycle") != null);

    // List should include it
    const list_result = try run(allocator, &.{
        runz_bin, "--root", state_dir, "list",
    });
    defer allocator.free(list_result.stdout);
    defer allocator.free(list_result.stderr);
    try std.testing.expectEqual(@as(u8, 0), list_result.exit_code);
    try std.testing.expect(std.mem.indexOf(u8, list_result.stdout, "test-lifecycle") != null);

    // Delete
    const delete_result = try run(allocator, &.{
        runz_bin, "--root", state_dir, "delete", "test-lifecycle",
    });
    defer allocator.free(delete_result.stdout);
    defer allocator.free(delete_result.stderr);
    try std.testing.expectEqual(@as(u8, 0), delete_result.exit_code);

    // State should fail now
    const state2_result = try run(allocator, &.{
        runz_bin, "--root", state_dir, "state", "test-lifecycle",
    });
    defer allocator.free(state2_result.stdout);
    defer allocator.free(state2_result.stderr);
    try std.testing.expect(state2_result.exit_code != 0);
}

// --- runz run (requires static busybox in the bundle) ---

test "cli: runz run with echo" {
    const allocator = std.testing.allocator;

    const ts: u64 = @intCast(std.time.timestamp());
    const state_dir = try std.fmt.allocPrint(allocator, "/tmp/runz-run-{x}", .{ts});
    defer allocator.free(state_dir);
    std.fs.makeDirAbsolute(state_dir) catch return;
    defer std.fs.deleteTreeAbsolute(state_dir) catch {};

    const config = try helpers.minimalConfig(allocator, &.{ "/bin/echo", "hello-from-runz-test" });
    defer allocator.free(config);
    const bundle = try helpers.createTestBundle(allocator, config);
    defer {
        helpers.cleanupBundle(bundle);
        allocator.free(bundle);
    }

    // runz run requires root for namespaces — skip if not root
    if (std.os.linux.getuid() != 0) return;

    const result = try run(allocator, &.{
        runz_bin, "--root", state_dir, "run", "run-test", "-b", bundle,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Container should have printed our message
    try std.testing.expect(
        std.mem.indexOf(u8, result.stdout, "hello-from-runz-test") != null or
            std.mem.indexOf(u8, result.stderr, "hello-from-runz-test") != null,
    );
}

test "cli: runz spec has valid mounts" {
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ runz_bin, "spec" });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try std.testing.expectEqual(@as(u8, 0), result.exit_code);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{});
    defer parsed.deinit();

    // Verify mounts include /proc, /dev, /sys
    const mounts = parsed.value.object.get("mounts") orelse return error.MissingField;
    try std.testing.expect(mounts.array.items.len >= 3);

    var has_proc = false;
    var has_dev = false;
    var has_sys = false;
    for (mounts.array.items) |m| {
        const dest = m.object.get("destination") orelse continue;
        if (dest == .string) {
            if (std.mem.eql(u8, dest.string, "/proc")) has_proc = true;
            if (std.mem.eql(u8, dest.string, "/dev")) has_dev = true;
            if (std.mem.eql(u8, dest.string, "/sys")) has_sys = true;
        }
    }
    try std.testing.expect(has_proc);
    try std.testing.expect(has_dev);
    try std.testing.expect(has_sys);
}
