const std = @import("std");
const runz = @import("runz");
const helpers = @import("helpers.zig");

// ============================================================================
// Layer 1: Library integration tests
// These test the runz library functions directly (no CLI subprocess).
// Require root or user namespace support.
// ============================================================================

// --- Runtime spec parsing ---

test "parse config.json and extract process args" {
    const allocator = std.testing.allocator;
    const config = try helpers.minimalConfig(allocator, &.{ "/bin/echo", "hello" });
    defer allocator.free(config);

    const spec = try runz.runtime_spec.parseConfig(allocator, config);
    try std.testing.expect(spec.process != null);
    try std.testing.expect(spec.process.?.args != null);
    try std.testing.expectEqual(@as(usize, 2), spec.process.?.args.?.len);
    try std.testing.expectEqualStrings("/bin/echo", spec.process.?.args.?[0]);
    try std.testing.expectEqualStrings("hello", spec.process.?.args.?[1]);

    // Cleanup allocated strings
    allocator.free(spec.ociVersion);
    if (spec.root) |r| allocator.free(r.path);
    if (spec.process) |p| {
        allocator.free(p.cwd);
        if (p.args) |args| {
            for (args) |a| allocator.free(a);
            allocator.free(args);
        }
        if (p.env) |env| {
            for (env) |e| allocator.free(e);
            allocator.free(env);
        }
    }
}

test "parse config.json with resource limits" {
    const allocator = std.testing.allocator;
    const config = try helpers.configWithLimits(allocator, &.{"/bin/true"}, 256 * 1024 * 1024, 100);
    defer allocator.free(config);

    const spec = try runz.runtime_spec.parseConfig(allocator, config);

    // Verify spec parses (detailed resource extraction is tested in runtime_spec unit tests)
    try std.testing.expect(spec.process != null);

    // Cleanup
    allocator.free(spec.ociVersion);
    if (spec.root) |r| allocator.free(r.path);
    if (spec.process) |p| {
        allocator.free(p.cwd);
        if (p.args) |args| {
            for (args) |a| allocator.free(a);
            allocator.free(args);
        }
        if (p.env) |env| {
            for (env) |e| allocator.free(e);
            allocator.free(env);
        }
    }
}

// --- Container manager ---

test "container manager create and delete" {
    const allocator = std.testing.allocator;

    const ts: u64 = @intCast(std.time.timestamp());
    const state_dir = try std.fmt.allocPrint(allocator, "/tmp/runz-state-{x}", .{ts});
    defer allocator.free(state_dir);
    std.fs.makeDirAbsolute(state_dir) catch return;
    defer std.fs.deleteTreeAbsolute(state_dir) catch {};

    var mgr = runz.container.Manager.init(allocator, state_dir);

    var info = mgr.create("test-1", "/tmp/fake-bundle", null) catch return;
    try std.testing.expectEqualStrings("test-1", info.id);
    try std.testing.expectEqual(runz.container.State.created, info.state);

    // Verify state file was created
    var path_buf: [256]u8 = undefined;
    const state_path = std.fmt.bufPrint(&path_buf, "{s}/test-1.json", .{state_dir}) catch unreachable;
    std.fs.accessAbsolute(state_path, .{}) catch {
        try std.testing.expect(false); // state file should exist
    };

    // List should include our container
    const ids = try mgr.list(allocator);
    defer {
        for (ids) |id| allocator.free(id);
        allocator.free(ids);
    }
    try std.testing.expect(ids.len >= 1);
    var found = false;
    for (ids) |id| {
        if (std.mem.eql(u8, id, "test-1")) found = true;
    }
    try std.testing.expect(found);

    // Delete
    mgr.delete(&info);

    // State file should be gone
    std.fs.accessAbsolute(state_path, .{}) catch return; // expected: gone
    try std.testing.expect(false); // if we get here, file still exists
}

test "container state JSON serialization" {
    const allocator = std.testing.allocator;
    const info = runz.container.ContainerInfo{
        .id = "json-test",
        .pid = 12345,
        .state = .running,
        .bundle = "/opt/bundle",
        .created = 1700000000,
        .allocator = allocator,
    };
    const json = try info.toJson(allocator);
    defer allocator.free(json);

    // Parse it back
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    const id = parsed.value.object.get("id") orelse return error.MissingField;
    try std.testing.expectEqualStrings("json-test", id.string);
    const status = parsed.value.object.get("status") orelse return error.MissingField;
    try std.testing.expectEqualStrings("running", status.string);
    const pid = parsed.value.object.get("pid") orelse return error.MissingField;
    try std.testing.expectEqual(@as(i64, 12345), pid.integer);
}

// --- Annotations ---

test "annotations parse and merge" {
    const allocator = std.testing.allocator;
    const json =
        \\{"org.opencontainers.image.title":"test","custom.key":"value"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    var annot = try runz.annotations.parseAnnotations(allocator, parsed.value);
    defer annot.deinit();

    try std.testing.expectEqualStrings("test", annot.get("org.opencontainers.image.title").?);
    try std.testing.expectEqualStrings("value", annot.get("custom.key").?);
}

// --- Capabilities ---

test "capability set from OCI names" {
    const caps = runz.linux_util.capabilities;
    const names = [_][]const u8{ "CAP_NET_RAW", "CAP_SYS_ADMIN", "CAP_CHOWN" };
    const set = caps.CapSet.fromNames(&names);
    try std.testing.expect(set.has(caps.CAP.NET_RAW));
    try std.testing.expect(set.has(caps.CAP.SYS_ADMIN));
    try std.testing.expect(set.has(caps.CAP.CHOWN));
    try std.testing.expect(!set.has(caps.CAP.SYS_MODULE));
}

// --- Cgroup version detection ---

test "cgroup version detection" {
    const cg = runz.linux_util.cgroup;
    const version = cg.detectVersion();
    // Should be either v1 or v2, just verify it doesn't crash
    try std.testing.expect(version == .v1 or version == .v2);
}

// --- Hook parsing ---

test "hook parsing from JSON" {
    const allocator = std.testing.allocator;
    const json =
        \\{"prestart":[{"path":"/usr/bin/setup","timeout":10}],"poststop":[{"path":"/usr/bin/cleanup"}]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    const hook_set = try runz.hooks.parseHooks(allocator, parsed.value);
    try std.testing.expectEqual(@as(usize, 1), hook_set.prestart.len);
    try std.testing.expectEqualStrings("/usr/bin/setup", hook_set.prestart[0].path);
    try std.testing.expectEqual(@as(u32, 10), hook_set.prestart[0].timeout.?);
    try std.testing.expectEqual(@as(usize, 1), hook_set.poststop.len);
    try std.testing.expectEqual(@as(usize, 0), hook_set.poststart.len);

    // Cleanup
    for (hook_set.prestart) |h| allocator.free(h.path);
    allocator.free(hook_set.prestart);
    for (hook_set.poststop) |h| allocator.free(h.path);
    allocator.free(hook_set.poststop);
}

// --- Netlink ---

test "netlink ipv4 address construction" {
    const nl = runz.linux_util.netlink;
    const addr = nl.ipv4(192, 168, 1, 1);
    const bytes: [4]u8 = @bitCast(addr);
    try std.testing.expectEqual(@as(u8, 192), bytes[0]);
    try std.testing.expectEqual(@as(u8, 168), bytes[1]);
    try std.testing.expectEqual(@as(u8, 1), bytes[2]);
    try std.testing.expectEqual(@as(u8, 1), bytes[3]);
}

// --- Security module availability ---

test "security module detection" {
    // Just verify the detection functions don't crash
    _ = runz.linux_util.security.isAppArmorAvailable();
    _ = runz.linux_util.security.isSELinuxAvailable();
}

// --- Propagation parsing ---

test "mount propagation parsing" {
    const prop = runz.linux_util.propagation;
    try std.testing.expectEqual(prop.Propagation.rprivate, prop.parsePropagation(&.{"rprivate"}).?);
    try std.testing.expectEqual(prop.Propagation.rshared, prop.parsePropagation(&.{"rshared"}).?);
    try std.testing.expectEqual(prop.Propagation.private, prop.parsePropagation(&.{ "nosuid", "private", "ro" }).?);
    try std.testing.expect(prop.parsePropagation(&.{"noexec"}) == null); // no propagation option
}
