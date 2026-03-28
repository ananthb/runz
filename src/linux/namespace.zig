const std = @import("std");
const linux = std.os.linux;
const syscall = @import("syscall.zig");
const log = @import("../log.zig");

const scoped_log = log.scoped("namespace");

pub const IsolationLevel = enum {
    full, // User + mount + PID + network namespaces + seccomp
    privileged, // Mount + PID + network namespaces (no user ns, requires root)
    chroot_only, // Bare chroot (fallback)
};

/// Detect the best available isolation level
pub fn detectIsolationLevel() IsolationLevel {
    // Check if running as root
    if (linux.getuid() == 0) {
        return .privileged;
    }

    // Check if unprivileged user namespaces are available
    const userns_available = blk: {
        const file = std.fs.openFileAbsolute("/proc/sys/kernel/unprivileged_userns_clone", .{}) catch {
            // File doesn't exist - user namespaces may still work (many kernels don't have this sysctl)
            break :blk true;
        };
        defer file.close();
        var buf: [8]u8 = undefined;
        const n = file.readAll(&buf) catch break :blk false;
        if (n > 0 and buf[0] == '1') {
            break :blk true;
        }
        break :blk false;
    };

    if (userns_available) {
        return .full;
    }

    return .chroot_only;
}

/// Write UID map for a child process
pub fn writeUidMap(child_pid: i32, outer_uid: u32) !void {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/uid_map", .{child_pid}) catch return error.InvalidArgument;

    var content_buf: [32]u8 = undefined;
    const content = std.fmt.bufPrint(&content_buf, "0 {d} 1\n", .{outer_uid}) catch return error.InvalidArgument;

    writeFileContent(path, content) catch |err| {
        scoped_log.err("Failed to write uid_map: {}", .{err});
        return err;
    };
}

/// Write GID map for a child process (must deny setgroups first)
pub fn writeGidMap(child_pid: i32, outer_gid: u32) !void {
    // Deny setgroups first (required on kernels 3.19+)
    var setgroups_buf: [64]u8 = undefined;
    const setgroups_path = std.fmt.bufPrint(&setgroups_buf, "/proc/{d}/setgroups", .{child_pid}) catch return error.InvalidArgument;
    writeFileContent(setgroups_path, "deny\n") catch {};

    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/gid_map", .{child_pid}) catch return error.InvalidArgument;

    var content_buf: [32]u8 = undefined;
    const content = std.fmt.bufPrint(&content_buf, "0 {d} 1\n", .{outer_gid}) catch return error.InvalidArgument;

    writeFileContent(path, content) catch |err| {
        scoped_log.err("Failed to write gid_map: {}", .{err});
        return err;
    };
}

fn writeFileContent(path: []const u8, content: []const u8) !void {
    const dir_path = std.fs.path.dirname(path) orelse "/";
    var dir = try std.fs.openDirAbsolute(dir_path, .{});
    defer dir.close();
    var file = try dir.openFile(std.fs.path.basename(path), .{ .mode = .write_only });
    defer file.close();
    try file.writeAll(content);
}

test "IsolationLevel enum" {
    const level = IsolationLevel.full;
    try std.testing.expect(level == .full);

    const chroot = IsolationLevel.chroot_only;
    try std.testing.expect(chroot == .chroot_only);
}

test "uid map content format" {
    // Verify the format we'd write to uid_map
    var buf: [32]u8 = undefined;
    const content = std.fmt.bufPrint(&buf, "0 {d} 1\n", .{@as(u32, 1000)}) catch unreachable;
    try std.testing.expectEqualStrings("0 1000 1\n", content);
}

test "gid map content format" {
    // Verify the format we'd write to gid_map
    var buf: [32]u8 = undefined;
    const content = std.fmt.bufPrint(&buf, "0 {d} 1\n", .{@as(u32, 1000)}) catch unreachable;
    try std.testing.expectEqualStrings("0 1000 1\n", content);
}
