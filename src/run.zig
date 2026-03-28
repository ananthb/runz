const std = @import("std");
const linux = std.os.linux;
const log = @import("log.zig");
const syscall = @import("linux/syscall.zig");
const mount_util = @import("linux/mount.zig");
const seccomp = @import("linux/seccomp.zig");
const namespace = @import("linux/namespace.zig");
const dev = @import("linux/dev.zig");

const scoped_log = log.scoped("run");

pub const RunError = error{
    CommandFailed,
    SetupFailed,
    OutOfMemory,
};

pub const IsolationMode = enum {
    auto,
    full,
    privileged,
    chroot_only,
};

pub const RunOptions = struct {
    isolation: IsolationMode = .auto,
    network: bool = true,
};

/// Execute a command inside a rootfs with container isolation.
/// Sets up namespaces, mounts, seccomp, and minimal /dev.
pub fn executeInRootfs(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    argv: []const []const u8,
    env: ?[]const []const u8,
) RunError!void {
    return executeInRootfsWithOptions(allocator, rootfs_path, argv, env, .{});
}

/// Execute a command inside a rootfs with container isolation and custom options.
pub fn executeInRootfsWithOptions(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    argv: []const []const u8,
    env: ?[]const []const u8,
    options: RunOptions,
) RunError!void {
    if (argv.len == 0) return;

    scoped_log.info("RUN: {s}", .{argv[0]});

    // Detect isolation level
    const isolation_level: namespace.IsolationLevel = switch (options.isolation) {
        .auto => namespace.detectIsolationLevel(),
        .full => .full,
        .privileged => .privileged,
        .chroot_only => .chroot_only,
    };

    scoped_log.info("Using isolation level: {s}", .{@tagName(isolation_level)});

    switch (isolation_level) {
        .full => return executeWithFullIsolation(allocator, rootfs_path, argv, env, options),
        .privileged => return executeWithPrivilegedIsolation(allocator, rootfs_path, argv, env, options),
        .chroot_only => return executeWithChrootOnly(allocator, rootfs_path, argv, env),
    }
}

/// Full isolation: user namespace + mount + PID + network namespaces + seccomp
fn executeWithFullIsolation(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    argv: []const []const u8,
    env: ?[]const []const u8,
    options: RunOptions,
) RunError!void {
    // Save caller's UID/GID before forking
    const outer_uid = linux.getuid();
    const outer_gid = linux.getgid();

    // Create pipes for parent<->child synchronization
    // pipe_to_child: parent writes, child reads (for uid/gid map signal)
    // pipe_to_parent: child writes, parent reads (child signals it's ready)
    const pipe_to_child = std.posix.pipe() catch {
        scoped_log.err("Failed to create pipe_to_child", .{});
        return error.SetupFailed;
    };
    const pipe_to_parent = std.posix.pipe() catch {
        scoped_log.err("Failed to create pipe_to_parent", .{});
        std.posix.close(pipe_to_child[0]);
        std.posix.close(pipe_to_child[1]);
        return error.SetupFailed;
    };

    const fork_result = doFork();
    if (fork_result == null) {
        scoped_log.err("fork failed", .{});
        return error.CommandFailed;
    }

    const child_pid = fork_result.?;

    if (child_pid == 0) {
        // === CHILD ===
        std.posix.close(pipe_to_child[1]); // close write end
        std.posix.close(pipe_to_parent[0]); // close read end

        // Step 1: Unshare user namespace
        syscall.unshareRaw(syscall.CloneFlags.CLONE_NEWUSER) catch {
            scoped_log.err("Failed to unshare user namespace, falling back to chroot", .{});
            std.posix.close(pipe_to_child[0]);
            std.posix.close(pipe_to_parent[1]);
            // Fall back: just do chroot exec
            runInChildChroot(allocator, rootfs_path, argv, env);
            std.process.exit(127);
        };

        // Step 2: Signal parent that we've unshared user ns
        _ = std.posix.write(pipe_to_parent[1], "r") catch {};
        std.posix.close(pipe_to_parent[1]);

        // Step 3: Wait for parent to write uid/gid maps
        var wait_buf: [1]u8 = undefined;
        _ = std.posix.read(pipe_to_child[0], &wait_buf) catch {};
        std.posix.close(pipe_to_child[0]);

        // Step 4: Unshare mount, PID, and optionally network namespaces
        var ns_flags: u32 = syscall.CloneFlags.CLONE_NEWNS | syscall.CloneFlags.CLONE_NEWPID;
        if (!options.network) {
            ns_flags |= syscall.CloneFlags.CLONE_NEWNET;
        }
        syscall.unshareRaw(ns_flags) catch |err| {
            scoped_log.err("Failed to unshare mount/PID namespace: {}", .{err});
            std.process.exit(126);
        };

        // Step 5: Make root private to prevent mount propagation
        syscall.mount(null, "/", null, .{ .private = true, .rec = true }, null) catch {};

        // Step 6: Setup mounts in rootfs
        setupIsolatedMounts(allocator, rootfs_path) catch |err| {
            scoped_log.warn("Mount setup failed: {}, continuing anyway", .{err});
        };

        // Step 7: Copy DNS config
        setupDns(allocator, rootfs_path) catch {};

        // Step 8: Double-fork for PID namespace (child becomes PID 1 in new ns)
        const inner_result = doFork();
        if (inner_result == null) {
            scoped_log.err("inner fork failed", .{});
            std.process.exit(126);
        }

        const grandchild_pid = inner_result.?;
        if (grandchild_pid == 0) {
            // === GRANDCHILD (PID 1 in new PID namespace) ===
            execInRootfs(allocator, rootfs_path, argv, env);
            std.process.exit(127);
        }

        // Child: wait for grandchild and propagate exit status
        const status = waitForChild(grandchild_pid);
        std.process.exit(status);
    }

    // === PARENT ===
    std.posix.close(pipe_to_child[0]); // close read end
    std.posix.close(pipe_to_parent[1]); // close write end

    // Wait for child to signal it has unshared user namespace
    var ready_buf: [1]u8 = undefined;
    _ = std.posix.read(pipe_to_parent[0], &ready_buf) catch {};
    std.posix.close(pipe_to_parent[0]);

    // Write UID/GID maps for the child
    namespace.writeUidMap(child_pid, outer_uid) catch |err| {
        scoped_log.warn("Failed to write uid_map: {}", .{err});
    };
    namespace.writeGidMap(child_pid, outer_gid) catch |err| {
        scoped_log.warn("Failed to write gid_map: {}", .{err});
    };

    // Signal child that maps are written
    _ = std.posix.write(pipe_to_child[1], "g") catch {};
    std.posix.close(pipe_to_child[1]);

    // Wait for child
    const exit_code = waitForChild(child_pid);
    if (exit_code != 0) {
        scoped_log.err("RUN command exited with status {}", .{exit_code});
        return error.CommandFailed;
    }
}

/// Privileged isolation: mount + PID + network namespaces (requires root, no user ns)
fn executeWithPrivilegedIsolation(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    argv: []const []const u8,
    env: ?[]const []const u8,
    options: RunOptions,
) RunError!void {
    const fork_result = doFork();
    if (fork_result == null) {
        scoped_log.err("fork failed", .{});
        return error.CommandFailed;
    }

    const child_pid = fork_result.?;

    if (child_pid == 0) {
        // === CHILD ===

        // Unshare mount, PID, and optionally network namespaces
        var ns_flags: u32 = syscall.CloneFlags.CLONE_NEWNS | syscall.CloneFlags.CLONE_NEWPID;
        if (!options.network) {
            ns_flags |= syscall.CloneFlags.CLONE_NEWNET;
        }
        syscall.unshareRaw(ns_flags) catch |err| {
            scoped_log.err("Failed to unshare namespaces: {}, falling back to chroot", .{err});
            runInChildChroot(allocator, rootfs_path, argv, env);
            std.process.exit(127);
        };

        // Make root private
        syscall.mount(null, "/", null, .{ .private = true, .rec = true }, null) catch {};

        // Setup mounts
        setupIsolatedMounts(allocator, rootfs_path) catch |err| {
            scoped_log.warn("Mount setup failed: {}, continuing anyway", .{err});
        };

        // Copy DNS
        setupDns(allocator, rootfs_path) catch {};

        // Double-fork for PID namespace
        const inner_result = doFork();
        if (inner_result == null) {
            scoped_log.err("inner fork failed", .{});
            std.process.exit(126);
        }

        const grandchild_pid = inner_result.?;
        if (grandchild_pid == 0) {
            // === GRANDCHILD ===
            execInRootfs(allocator, rootfs_path, argv, env);
            std.process.exit(127);
        }

        // Child: wait for grandchild
        const status = waitForChild(grandchild_pid);
        std.process.exit(status);
    }

    // === PARENT ===
    const exit_code = waitForChild(child_pid);
    if (exit_code != 0) {
        scoped_log.err("RUN command exited with status {}", .{exit_code});
        return error.CommandFailed;
    }
}

/// Chroot-only fallback (no namespace isolation)
fn executeWithChrootOnly(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    argv: []const []const u8,
    env: ?[]const []const u8,
) RunError!void {
    setupMountsLegacy(allocator, rootfs_path) catch |err| {
        scoped_log.warn("Mount setup failed: {}, continuing anyway", .{err});
    };
    defer cleanupMountsLegacy(allocator, rootfs_path);

    setupDns(allocator, rootfs_path) catch {};

    const fork_result = doFork();
    if (fork_result == null) {
        scoped_log.err("fork failed", .{});
        return error.CommandFailed;
    }

    const child_pid = fork_result.?;

    if (child_pid == 0) {
        // Child: chroot + exec
        runInChildChroot(allocator, rootfs_path, argv, env);
        std.process.exit(127);
    }

    // Parent: wait for child
    const exit_code = waitForChild(child_pid);
    if (exit_code != 0) {
        scoped_log.err("RUN command exited with status {}", .{exit_code});
        return error.CommandFailed;
    }
}

// === Helper functions ===

/// Fork, handling aarch64 compatibility (use clone instead of fork)
fn doFork() ?i32 {
    const fork_result = if (@hasField(linux.SYS, "fork"))
        linux.syscall0(.fork)
    else
        linux.syscall5(.clone, linux.SIG.CHLD, 0, 0, 0, 0);

    if (linux.E.init(fork_result) != .SUCCESS) {
        return null;
    }

    return @intCast(fork_result);
}

/// Wait for a child process, return its exit code
fn waitForChild(child_pid: i32) u8 {
    var status: u32 = 0;
    while (true) {
        const wait_result = linux.syscall4(
            .wait4,
            @as(usize, @intCast(child_pid)),
            @intFromPtr(&status),
            0,
            0,
        );
        if (linux.E.init(wait_result) == .INTR) continue;
        break;
    }
    return @intCast((status >> 8) & 0xFF);
}

/// Execute command after chroot+chdir, installing seccomp filter
fn execInRootfs(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    argv: []const []const u8,
    env: ?[]const []const u8,
) void {
    const rootfs_z = allocator.dupeZ(u8, rootfs_path) catch return;

    syscall.chroot(rootfs_z) catch {
        std.debug.print("oci-zig: chroot failed\n", .{});
        return;
    };
    syscall.chdir("/") catch return;

    // Install seccomp filter before exec
    var filter = seccomp.defaultFilter();
    filter.install() catch |err| {
        scoped_log.warn("Failed to install seccomp filter: {}, continuing without it", .{err});
    };

    // Build null-terminated argv
    var c_argv: std.ArrayListUnmanaged(?[*:0]const u8) = .{};
    for (argv) |arg| {
        const z = allocator.dupeZ(u8, arg) catch return;
        c_argv.append(allocator, z) catch return;
    }
    c_argv.append(allocator, null) catch return;

    // Build null-terminated envp
    var c_envp: std.ArrayListUnmanaged(?[*:0]const u8) = .{};
    if (env) |env_list| {
        for (env_list) |e| {
            const z = allocator.dupeZ(u8, e) catch return;
            c_envp.append(allocator, z) catch return;
        }
    } else {
        for ([_][]const u8{
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/root",
            "TERM=xterm",
        }) |e| {
            const z = allocator.dupeZ(u8, e) catch return;
            c_envp.append(allocator, z) catch return;
        }
    }
    c_envp.append(allocator, null) catch return;

    const cmd_z = allocator.dupeZ(u8, argv[0]) catch return;
    const err = std.posix.execveZ(cmd_z, @ptrCast(c_argv.items.ptr), @ptrCast(c_envp.items.ptr));
    std.debug.print("oci-zig: execve failed: {}\n", .{err});
}

/// Chroot-only exec (no seccomp, used as fallback)
fn runInChildChroot(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    argv: []const []const u8,
    env: ?[]const []const u8,
) void {
    const rootfs_z = allocator.dupeZ(u8, rootfs_path) catch return;
    syscall.chroot(rootfs_z) catch {
        std.debug.print("oci-zig: chroot failed\n", .{});
        return;
    };
    syscall.chdir("/") catch return;

    // Build null-terminated argv
    var c_argv: std.ArrayListUnmanaged(?[*:0]const u8) = .{};
    for (argv) |arg| {
        const z = allocator.dupeZ(u8, arg) catch return;
        c_argv.append(allocator, z) catch return;
    }
    c_argv.append(allocator, null) catch return;

    // Build null-terminated envp
    var c_envp: std.ArrayListUnmanaged(?[*:0]const u8) = .{};
    if (env) |env_list| {
        for (env_list) |e| {
            const z = allocator.dupeZ(u8, e) catch return;
            c_envp.append(allocator, z) catch return;
        }
    } else {
        for ([_][]const u8{
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/root",
            "TERM=xterm",
        }) |e| {
            const z = allocator.dupeZ(u8, e) catch return;
            c_envp.append(allocator, z) catch return;
        }
    }
    c_envp.append(allocator, null) catch return;

    const cmd_z = allocator.dupeZ(u8, argv[0]) catch return;
    const err = std.posix.execveZ(cmd_z, @ptrCast(c_argv.items.ptr), @ptrCast(c_envp.items.ptr));
    std.debug.print("oci-zig: execve failed: {}\n", .{err});
}

/// Set up mounts for isolated (namespace) mode: bind rootfs, proc (read-only), sysfs, minimal /dev
fn setupIsolatedMounts(allocator: std.mem.Allocator, rootfs_path: []const u8) !void {
    // Ensure directories exist
    {
        var dir = std.fs.openDirAbsolute(rootfs_path, .{}) catch return error.SetupFailed;
        defer dir.close();
        dir.makePath("proc") catch {};
        dir.makePath("dev") catch {};
        dir.makePath("sys") catch {};
        dir.makePath("etc") catch {};
        dir.makePath("tmp") catch {};
    }

    // Mount proc
    const proc_path = std.fmt.allocPrint(allocator, "{s}/proc", .{rootfs_path}) catch return error.OutOfMemory;
    defer allocator.free(proc_path);
    {
        var proc_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (proc_path.len < proc_buf.len) {
            @memcpy(proc_buf[0..proc_path.len], proc_path);
            proc_buf[proc_path.len] = 0;
            const proc_z: [*:0]const u8 = @ptrCast(proc_buf[0..proc_path.len :0]);
            syscall.mount("proc", proc_z, "proc", .{ .nosuid = true, .noexec = true, .nodev = true }, null) catch {};
        }
    }

    // Mount sysfs (read-only bind)
    const sys_path = std.fmt.allocPrint(allocator, "{s}/sys", .{rootfs_path}) catch return error.OutOfMemory;
    defer allocator.free(sys_path);
    {
        var sys_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (sys_path.len < sys_buf.len) {
            @memcpy(sys_buf[0..sys_path.len], sys_path);
            sys_buf[sys_path.len] = 0;
            const sys_z: [*:0]const u8 = @ptrCast(sys_buf[0..sys_path.len :0]);
            // Try bind mount first, then remount read-only
            syscall.mount("/sys", sys_z, null, .{ .bind = true, .rec = true }, null) catch {
                // If bind mount fails, try mounting sysfs directly
                syscall.mount("sysfs", sys_z, "sysfs", .{ .rdonly = true, .nosuid = true, .noexec = true, .nodev = true }, null) catch {};
            };
            // Remount read-only
            syscall.mount(null, sys_z, null, .{ .remount = true, .bind = true, .rdonly = true }, null) catch {};
        }
    }

    // Setup minimal /dev
    dev.setupMinimalDev(allocator, rootfs_path) catch |err| {
        scoped_log.warn("Minimal /dev setup failed: {}, falling back to bind mount", .{err});
        // Fallback: bind mount host /dev
        const dev_path = std.fmt.allocPrint(allocator, "{s}/dev", .{rootfs_path}) catch return;
        defer allocator.free(dev_path);
        var dev_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (dev_path.len < dev_buf.len) {
            @memcpy(dev_buf[0..dev_path.len], dev_path);
            dev_buf[dev_path.len] = 0;
            const dev_z: [*:0]const u8 = @ptrCast(dev_buf[0..dev_path.len :0]);
            syscall.mount("/dev", dev_z, null, .{ .bind = true, .rec = true }, null) catch {};
        }
    };

    // Mount tmpfs on /tmp
    const tmp_path = std.fmt.allocPrint(allocator, "{s}/tmp", .{rootfs_path}) catch return error.OutOfMemory;
    defer allocator.free(tmp_path);
    {
        var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (tmp_path.len < tmp_buf.len) {
            @memcpy(tmp_buf[0..tmp_path.len], tmp_path);
            tmp_buf[tmp_path.len] = 0;
            const tmp_z: [*:0]const u8 = @ptrCast(tmp_buf[0..tmp_path.len :0]);
            syscall.mount("tmpfs", tmp_z, "tmpfs", .{ .nosuid = true, .nodev = true }, @ptrCast("size=65536k,mode=1777")) catch {};
        }
    }
}

/// Legacy mount setup (for chroot_only mode, same as old behavior)
fn setupMountsLegacy(allocator: std.mem.Allocator, rootfs_path: []const u8) !void {
    {
        var dir = try std.fs.openDirAbsolute(rootfs_path, .{});
        defer dir.close();
        dir.makePath("proc") catch {};
        dir.makePath("dev") catch {};
        dir.makePath("sys") catch {};
        dir.makePath("etc") catch {};
    }

    const MS_NOSUID: u32 = 2;
    const MS_NOEXEC: u32 = 8;
    const MS_NODEV: u32 = 4;
    const MS_BIND: u32 = 4096;
    const MS_REC: u32 = 16384;

    // Mount /proc
    const proc_path_str = try std.fmt.allocPrint(allocator, "{s}/proc", .{rootfs_path});
    defer allocator.free(proc_path_str);
    const proc_path = try allocator.dupeZ(u8, proc_path_str);
    defer allocator.free(proc_path[0 .. proc_path_str.len + 1]);
    sysMount("proc", proc_path, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV);

    // Bind mount /dev
    const dev_path_str = try std.fmt.allocPrint(allocator, "{s}/dev", .{rootfs_path});
    defer allocator.free(dev_path_str);
    const dev_path = try allocator.dupeZ(u8, dev_path_str);
    defer allocator.free(dev_path[0 .. dev_path_str.len + 1]);
    sysMount("/dev", dev_path, null, MS_BIND | MS_REC);

    // Bind mount /sys
    const sys_path_str = try std.fmt.allocPrint(allocator, "{s}/sys", .{rootfs_path});
    defer allocator.free(sys_path_str);
    const sys_path = try allocator.dupeZ(u8, sys_path_str);
    defer allocator.free(sys_path[0 .. sys_path_str.len + 1]);
    sysMount("/sys", sys_path, null, MS_BIND | MS_REC);
}

fn cleanupMountsLegacy(allocator: std.mem.Allocator, rootfs_path: []const u8) void {
    const MNT_DETACH: u32 = 2;
    for ([_][]const u8{ "/sys", "/dev", "/proc" }) |suffix| {
        const path = std.fmt.allocPrint(allocator, "{s}{s}", .{ rootfs_path, suffix }) catch continue;
        defer allocator.free(path);
        const path_z = allocator.dupeZ(u8, path) catch continue;
        defer allocator.free(path_z[0 .. path.len + 1]);
        _ = linux.syscall2(.umount2, @intFromPtr(path_z), MNT_DETACH);
    }
}

fn sysMount(source: [*:0]const u8, target: [*:0]const u8, fstype: ?[*:0]const u8, flags: u32) void {
    _ = linux.syscall5(
        .mount,
        @intFromPtr(source),
        @intFromPtr(target),
        if (fstype) |f| @intFromPtr(f) else 0,
        flags,
        0,
    );
}

fn setupDns(allocator: std.mem.Allocator, rootfs_path: []const u8) !void {
    const dst_path = try std.fmt.allocPrint(allocator, "{s}/etc/resolv.conf", .{rootfs_path});
    defer allocator.free(dst_path);

    const src = std.fs.openFileAbsolute("/etc/resolv.conf", .{}) catch return;
    defer src.close();

    const dir_path = std.fs.path.dirname(dst_path) orelse "/";
    var dir = std.fs.openDirAbsolute(dir_path, .{}) catch return;
    defer dir.close();
    var dst = dir.createFile(std.fs.path.basename(dst_path), .{}) catch return;
    defer dst.close();

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = src.readAll(&buf) catch break;
        if (n == 0) break;
        dst.writeAll(buf[0..n]) catch break;
        if (n < buf.len) break;
    }
}

test "RunError type" {
    const err: RunError = error.CommandFailed;
    _ = err;
}

test "RunOptions defaults" {
    const opts = RunOptions{};
    try std.testing.expect(opts.isolation == .auto);
    try std.testing.expect(opts.network == true);
}

test "IsolationMode enum" {
    try std.testing.expect(@intFromEnum(IsolationMode.auto) == 0);
    try std.testing.expect(@intFromEnum(IsolationMode.full) == 1);
    try std.testing.expect(@intFromEnum(IsolationMode.privileged) == 2);
    try std.testing.expect(@intFromEnum(IsolationMode.chroot_only) == 3);
}
