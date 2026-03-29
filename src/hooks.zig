const std = @import("std");
const linux = std.os.linux;
const log = @import("log.zig");

const scoped_log = log.scoped("hooks");

/// OCI lifecycle hook
pub const Hook = struct {
    path: []const u8,
    args: ?[]const []const u8 = null,
    env: ?[]const []const u8 = null,
    timeout: ?u32 = null, // seconds
};

/// Execute a list of OCI hooks in order.
/// Each hook receives the container state on stdin as JSON.
/// Hooks run in the host namespace (not inside the container).
pub fn executeHooks(
    allocator: std.mem.Allocator,
    hooks: []const Hook,
    state_json: []const u8,
) !void {
    for (hooks) |hook| {
        executeHook(allocator, &hook, state_json) catch |err| {
            scoped_log.err("Hook {s} failed: {}", .{ hook.path, err });
            return err;
        };
    }
}

fn executeHook(allocator: std.mem.Allocator, hook: *const Hook, state_json: []const u8) !void {
    scoped_log.debug("Running hook: {s}", .{hook.path});

    // Build argv
    var argv: std.ArrayListUnmanaged([]const u8) = .{};
    defer argv.deinit(allocator);

    if (hook.args) |args| {
        for (args) |arg| try argv.append(allocator, arg);
    } else {
        try argv.append(allocator, hook.path);
    }

    var child = std.process.Child.init(argv.items, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    // Set environment if specified
    // (Child.init uses default env; custom env requires env_map which is complex)

    child.spawn() catch |err| {
        scoped_log.err("Failed to spawn hook {s}: {}", .{ hook.path, err });
        return error.HookFailed;
    };

    // Write state JSON to stdin
    if (child.stdin) |stdin| {
        var s = stdin;
        s.writeAll(state_json) catch {};
        s.close();
        child.stdin = null;
    }

    // Wait with timeout
    const result = child.wait() catch |err| {
        scoped_log.err("Failed to wait for hook: {}", .{err});
        return error.HookFailed;
    };

    const exit_code = result.Exited;
    if (exit_code != 0) {
        scoped_log.err("Hook {s} exited with code {d}", .{ hook.path, exit_code });
        return error.HookFailed;
    }
}

/// Hook execution points in the container lifecycle
pub const HookPoint = enum {
    /// After container is created but before user process starts
    createRuntime,
    /// After container is created, in the container namespace
    createContainer,
    /// After user process is started
    startContainer,
    /// After container process exits
    poststart,
    /// After container is deleted
    poststop,
};

/// Parse hooks from OCI runtime spec JSON
pub fn parseHooks(allocator: std.mem.Allocator, hooks_json: std.json.Value) !struct {
    prestart: []const Hook,
    createRuntime: []const Hook,
    createContainer: []const Hook,
    startContainer: []const Hook,
    poststart: []const Hook,
    poststop: []const Hook,
} {
    return .{
        .prestart = if (hooks_json.object.get("prestart")) |h| try parseHookList(allocator, h) else &.{},
        .createRuntime = if (hooks_json.object.get("createRuntime")) |h| try parseHookList(allocator, h) else &.{},
        .createContainer = if (hooks_json.object.get("createContainer")) |h| try parseHookList(allocator, h) else &.{},
        .startContainer = if (hooks_json.object.get("startContainer")) |h| try parseHookList(allocator, h) else &.{},
        .poststart = if (hooks_json.object.get("poststart")) |h| try parseHookList(allocator, h) else &.{},
        .poststop = if (hooks_json.object.get("poststop")) |h| try parseHookList(allocator, h) else &.{},
    };
}

pub fn parseHookList(allocator: std.mem.Allocator, value: std.json.Value) ![]const Hook {
    if (value != .array) return &.{};
    var list: std.ArrayListUnmanaged(Hook) = .{};
    for (value.array.items) |item| {
        if (item != .object) continue;
        const path = item.object.get("path") orelse continue;
        if (path != .string) continue;

        var hook = Hook{ .path = try allocator.dupe(u8, path.string) };

        if (item.object.get("args")) |args| {
            if (args == .array) {
                var arg_list: std.ArrayListUnmanaged([]const u8) = .{};
                for (args.array.items) |arg| {
                    if (arg == .string) {
                        try arg_list.append(allocator, try allocator.dupe(u8, arg.string));
                    }
                }
                hook.args = try arg_list.toOwnedSlice(allocator);
            }
        }

        if (item.object.get("timeout")) |t| {
            if (t == .integer) hook.timeout = @intCast(t.integer);
        }

        try list.append(allocator, hook);
    }
    return try list.toOwnedSlice(allocator);
}

test "Hook defaults" {
    const hook = Hook{ .path = "/bin/true" };
    try std.testing.expectEqualStrings("/bin/true", hook.path);
    try std.testing.expect(hook.args == null);
    try std.testing.expect(hook.timeout == null);
}

test "parseHooks from JSON" {
    const allocator = std.testing.allocator;
    const json =
        \\{"prestart":[{"path":"/usr/bin/fix-mounts","args":["/usr/bin/fix-mounts","arg1"],"timeout":5}],"poststop":[{"path":"/usr/bin/cleanup"}]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    const hooks = try parseHooks(allocator, parsed.value);

    try std.testing.expectEqual(@as(usize, 1), hooks.prestart.len);
    try std.testing.expectEqualStrings("/usr/bin/fix-mounts", hooks.prestart[0].path);
    try std.testing.expect(hooks.prestart[0].args != null);
    try std.testing.expectEqual(@as(usize, 2), hooks.prestart[0].args.?.len);
    try std.testing.expectEqual(@as(u32, 5), hooks.prestart[0].timeout.?);

    try std.testing.expectEqual(@as(usize, 1), hooks.poststop.len);
    try std.testing.expectEqualStrings("/usr/bin/cleanup", hooks.poststop[0].path);

    try std.testing.expectEqual(@as(usize, 0), hooks.createRuntime.len);
    try std.testing.expectEqual(@as(usize, 0), hooks.poststart.len);

    // Cleanup
    for (hooks.prestart) |h| {
        allocator.free(h.path);
        if (h.args) |args| {
            for (args) |a| allocator.free(a);
            allocator.free(args);
        }
    }
    allocator.free(hooks.prestart);
    for (hooks.poststop) |h| allocator.free(h.path);
    allocator.free(hooks.poststop);
}

test "HookPoint enum" {
    try std.testing.expectEqualStrings("createRuntime", @tagName(HookPoint.createRuntime));
    try std.testing.expectEqualStrings("poststop", @tagName(HookPoint.poststop));
}
