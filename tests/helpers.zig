const std = @import("std");

/// Create a minimal rootfs bundle for testing.
/// Returns the bundle path (caller must call cleanup).
pub fn createTestBundle(allocator: std.mem.Allocator, config_json: []const u8) ![]const u8 {
    // Create temp directory using timestamp for uniqueness
    const ts: u64 = @intCast(std.time.timestamp());
    const bundle = try std.fmt.allocPrint(allocator, "/tmp/runz-test-{x}", .{ts});
    std.fs.makeDirAbsolute(bundle) catch return error.SetupFailed;

    // Create rootfs directory structure
    var dir = try std.fs.openDirAbsolute(bundle, .{});
    defer dir.close();

    const dirs = [_][]const u8{
        "rootfs/bin",     "rootfs/dev", "rootfs/etc",
        "rootfs/proc",    "rootfs/sys", "rootfs/tmp",
        "rootfs/usr/bin", "rootfs/var",
    };
    for (dirs) |d| dir.makePath(d) catch {};

    // Copy busybox into rootfs.
    // BUSYBOX env var overrides, then try common paths (prefer static for container use).
    const env_busybox = std.posix.getenv("BUSYBOX");
    const busybox_search = [_][]const u8{
        "/nix/store/8mf4s8c4xjvlkj12p299qylrb30g7zzh-busybox-static-x86_64-unknown-linux-musl-1.37.0/bin/busybox",
        "/bin/busybox",
        "/usr/bin/busybox",
    };
    var busybox_paths_buf: [4][]const u8 = undefined;
    var busybox_count: usize = 0;
    if (env_busybox) |eb| {
        busybox_paths_buf[busybox_count] = eb;
        busybox_count += 1;
    }
    for (busybox_search) |p| {
        if (busybox_count < busybox_paths_buf.len) {
            busybox_paths_buf[busybox_count] = p;
            busybox_count += 1;
        }
    }
    const busybox_paths = busybox_paths_buf[0..busybox_count];
    var copied = false;
    for (busybox_paths) |src| {
        const dest = std.fmt.allocPrint(allocator, "{s}/rootfs/bin/busybox", .{bundle}) catch continue;
        defer allocator.free(dest);
        std.fs.copyFileAbsolute(src, dest, .{}) catch continue;
        copied = true;
        break;
    }
    if (!copied) {
        // Try 'which busybox' result
        return error.BusyboxNotFound;
    }

    // Create symlinks for sh, ls, cat, echo, etc.
    {
        var rootfs_bin = dir.openDir("rootfs/bin", .{}) catch return error.SetupFailed;
        defer rootfs_bin.close();
        const links = [_][]const u8{ "sh", "ls", "cat", "echo", "sleep", "id", "uname", "hostname", "ps", "mount", "true", "false" };
        for (links) |name| {
            rootfs_bin.symLink("busybox", name, .{}) catch {};
        }
    }

    // Write config.json
    {
        var config_file = dir.createFile("config.json", .{}) catch return error.SetupFailed;
        defer config_file.close();
        config_file.writeAll(config_json) catch return error.SetupFailed;
    }

    return bundle;
}

/// Clean up a test bundle
pub fn cleanupBundle(path: []const u8) void {
    std.fs.deleteTreeAbsolute(path) catch {};
}

/// Minimal OCI config.json for testing
pub fn minimalConfig(allocator: std.mem.Allocator, args: []const []const u8) ![]const u8 {
    var args_json: std.ArrayListUnmanaged(u8) = .{};
    defer args_json.deinit(allocator);
    try args_json.appendSlice(allocator, "[");
    for (args, 0..) |arg, i| {
        if (i > 0) try args_json.appendSlice(allocator, ",");
        try args_json.appendSlice(allocator, "\"");
        try args_json.appendSlice(allocator, arg);
        try args_json.appendSlice(allocator, "\"");
    }
    try args_json.appendSlice(allocator, "]");

    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "ociVersion": "1.0.2",
        \\  "process": {{
        \\    "args": {s},
        \\    "cwd": "/",
        \\    "env": ["PATH=/bin:/usr/bin","HOME=/root","TERM=xterm"]
        \\  }},
        \\  "root": {{"path": "rootfs"}},
        \\  "linux": {{
        \\    "namespaces": [
        \\      {{"type": "pid"}},
        \\      {{"type": "mount"}}
        \\    ]
        \\  }}
        \\}}
    , .{args_json.items});
}

/// Config with resource limits for cgroup testing
pub fn configWithLimits(allocator: std.mem.Allocator, args: []const []const u8, memory_limit: u64, pids_max: u32) ![]const u8 {
    var args_json: std.ArrayListUnmanaged(u8) = .{};
    defer args_json.deinit(allocator);
    try args_json.appendSlice(allocator, "[");
    for (args, 0..) |arg, i| {
        if (i > 0) try args_json.appendSlice(allocator, ",");
        try args_json.appendSlice(allocator, "\"");
        try args_json.appendSlice(allocator, arg);
        try args_json.appendSlice(allocator, "\"");
    }
    try args_json.appendSlice(allocator, "]");

    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "ociVersion": "1.0.2",
        \\  "process": {{
        \\    "args": {s},
        \\    "cwd": "/",
        \\    "env": ["PATH=/bin:/usr/bin","HOME=/root"]
        \\  }},
        \\  "root": {{"path": "rootfs"}},
        \\  "linux": {{
        \\    "namespaces": [
        \\      {{"type": "pid"}},
        \\      {{"type": "mount"}}
        \\    ],
        \\    "resources": {{
        \\      "memory": {{"limit": {d}}},
        \\      "pids": {{"limit": {d}}}
        \\    }}
        \\  }}
        \\}}
    , .{ args_json.items, memory_limit, pids_max });
}

/// Config with network namespace
pub fn configWithNetwork(allocator: std.mem.Allocator, args: []const []const u8) ![]const u8 {
    var args_json: std.ArrayListUnmanaged(u8) = .{};
    defer args_json.deinit(allocator);
    try args_json.appendSlice(allocator, "[");
    for (args, 0..) |arg, i| {
        if (i > 0) try args_json.appendSlice(allocator, ",");
        try args_json.appendSlice(allocator, "\"");
        try args_json.appendSlice(allocator, arg);
        try args_json.appendSlice(allocator, "\"");
    }
    try args_json.appendSlice(allocator, "]");

    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "ociVersion": "1.0.2",
        \\  "process": {{
        \\    "args": {s},
        \\    "cwd": "/",
        \\    "env": ["PATH=/bin:/usr/bin","HOME=/root"]
        \\  }},
        \\  "root": {{"path": "rootfs"}},
        \\  "linux": {{
        \\    "namespaces": [
        \\      {{"type": "pid"}},
        \\      {{"type": "mount"}},
        \\      {{"type": "network"}}
        \\    ]
        \\  }}
        \\}}
    , .{args_json.items});
}
