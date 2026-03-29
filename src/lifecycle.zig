const std = @import("std");
const linux = std.os.linux;
const log = @import("log.zig");
const run = @import("run.zig");
const runtime_spec = @import("runtime_spec.zig");
const spec_mount = @import("spec_mount.zig");
const capabilities = @import("linux/capabilities.zig");
const syscall = @import("linux/syscall.zig");
const mount_util = @import("linux/mount.zig");
const paths = @import("linux/paths.zig");
const hooks = @import("hooks.zig");
const namespace = @import("linux/namespace.zig");

const scoped_log = log.scoped("lifecycle");

pub const LifecycleError = error{
    InvalidSpec,
    CreateFailed,
    StartFailed,
    OutOfMemory,
    SetupFailed,
};

/// Create a container: fork, set up namespaces and mounts, then block on a FIFO
/// waiting for `start` to signal. Returns the child PID.
pub fn create(
    allocator: std.mem.Allocator,
    container_id: []const u8,
    bundle_path: []const u8,
    root_dir: []const u8,
) LifecycleError!i32 {
    // Parse config.json
    const config_path = std.fmt.allocPrint(allocator, "{s}/config.json", .{bundle_path}) catch
        return error.OutOfMemory;
    defer allocator.free(config_path);

    const spec = runtime_spec.parseConfigFile(allocator, config_path) catch
        return error.InvalidSpec;

    const root = spec.root orelse return error.InvalidSpec;
    const process = spec.process orelse return error.InvalidSpec;
    const argv = process.args orelse return error.InvalidSpec;
    if (argv.len == 0) return error.InvalidSpec;

    // Resolve rootfs
    const rootfs_path = if (std.fs.path.isAbsolute(root.path))
        allocator.dupe(u8, root.path) catch return error.OutOfMemory
    else
        std.fmt.allocPrint(allocator, "{s}/{s}", .{ bundle_path, root.path }) catch return error.OutOfMemory;
    defer allocator.free(rootfs_path);

    // Create container directory with FIFO
    const container_dir = std.fmt.allocPrint(allocator, "{s}/{s}", .{ root_dir, container_id }) catch return error.OutOfMemory;
    defer allocator.free(container_dir);
    {
        var rd = std.fs.openDirAbsolute("/", .{}) catch return error.SetupFailed;
        defer rd.close();
        rd.makePath(container_dir[1..]) catch return error.SetupFailed;
    }

    const fifo_path = std.fmt.allocPrint(allocator, "{s}/exec.fifo", .{container_dir}) catch return error.OutOfMemory;
    defer allocator.free(fifo_path);

    // Create FIFO using mknodat (S_IFIFO | 0600)
    {
        const fifo_z = std.posix.toPosixPath(fifo_path) catch return error.SetupFailed;
        const AT_FDCWD: usize = @bitCast(@as(isize, -100));
        const S_IFIFO: u32 = 0o010000;
        _ = linux.syscall4(.mknodat, AT_FDCWD, @intFromPtr(&fifo_z), S_IFIFO | 0o600, 0);
    }

    // Fork the container init process
    const fork_result = if (@hasField(linux.SYS, "fork"))
        linux.syscall0(.fork)
    else
        linux.syscall5(.clone, linux.SIG.CHLD, 0, 0, 0, 0);

    if (linux.E.init(fork_result) != .SUCCESS) {
        return error.CreateFailed;
    }

    const child_pid: i32 = @bitCast(@as(u32, @truncate(fork_result)));

    if (child_pid == 0) {
        // === CHILD: Container init process ===

        // Unshare namespaces
        var ns_flags: u32 = syscall.CloneFlags.CLONE_NEWNS | syscall.CloneFlags.CLONE_NEWPID;
        if (spec.linux) |lnx| {
            if (lnx.namespaces) |namespaces| {
                for (namespaces) |ns| {
                    if (std.mem.eql(u8, ns.type, "network")) ns_flags |= syscall.CloneFlags.CLONE_NEWNET;
                    if (std.mem.eql(u8, ns.type, "uts")) ns_flags |= 0x04000000; // CLONE_NEWUTS
                    if (std.mem.eql(u8, ns.type, "ipc")) ns_flags |= 0x08000000; // CLONE_NEWIPC
                }
            }
        }
        syscall.unshareRaw(ns_flags) catch {
            std.process.exit(126);
        };

        // Make root private
        syscall.mount(null, "/", null, .{ .private = true, .rec = true }, null) catch {};

        // Apply spec mounts
        if (spec.mounts) |mounts| {
            spec_mount.applySpecMounts(allocator, rootfs_path, mounts);
        } else {
            // Default mounts if none specified
            run.setupContainerMountsPublic(allocator, rootfs_path);
        }

        // Apply masked/readonly paths
        if (spec.linux) |lnx| {
            if (lnx.maskedPaths) |mp| paths.applyMaskedPaths(rootfs_path, mp, allocator);
            if (lnx.readonlyPaths) |rp| paths.applyReadonlyPaths(rootfs_path, rp, allocator);
        }

        // Block on FIFO — wait for `start` command
        scoped_log.debug("Container init blocking on FIFO", .{});
        const fifo_fd = std.fs.openFileAbsolute(fifo_path, .{}) catch {
            std.process.exit(126);
        };
        var wait_buf: [1]u8 = undefined;
        _ = fifo_fd.readAll(&wait_buf) catch {};
        fifo_fd.close();

        // FIFO signaled — now exec
        // Double-fork for PID namespace
        const inner_result = if (@hasField(linux.SYS, "fork"))
            linux.syscall0(.fork)
        else
            linux.syscall5(.clone, linux.SIG.CHLD, 0, 0, 0, 0);

        if (linux.E.init(inner_result) != .SUCCESS) std.process.exit(126);

        const grandchild: i32 = @bitCast(@as(u32, @truncate(inner_result)));
        if (grandchild == 0) {
            // Grandchild: pivot_root and exec
            doContainerExec(allocator, rootfs_path, argv, process.env, process.cwd);
            std.process.exit(127);
        }

        // Child: wait for grandchild
        var status: u32 = 0;
        while (true) {
            const wr = linux.syscall4(.wait4, @as(usize, @intCast(grandchild)), @intFromPtr(&status), 0, 0);
            if (linux.E.init(wr) == .INTR) continue;
            break;
        }
        std.process.exit(@intCast((status >> 8) & 0xFF));
    }

    // === PARENT ===
    scoped_log.info("Container {s} created (pid={d})", .{ container_id, child_pid });

    // Write state
    const state_json = std.fmt.allocPrint(allocator,
        \\{{"ociVersion":"1.0.2","id":"{s}","status":"created","pid":{d},"bundle":"{s}"}}
    , .{ container_id, child_pid, bundle_path }) catch return error.OutOfMemory;
    defer allocator.free(state_json);

    const state_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ root_dir, container_id }) catch return error.OutOfMemory;
    defer allocator.free(state_path);

    {
        const dir_path = std.fs.path.dirname(state_path) orelse "/";
        var dir = std.fs.openDirAbsolute(dir_path, .{}) catch return error.SetupFailed;
        defer dir.close();
        var file = dir.createFile(std.fs.path.basename(state_path), .{}) catch return error.SetupFailed;
        defer file.close();
        file.writeAll(state_json) catch return error.SetupFailed;
    }

    return child_pid;
}

/// Start a container: write to the FIFO to release the init process
pub fn start(
    allocator: std.mem.Allocator,
    container_id: []const u8,
    root_dir: []const u8,
) LifecycleError!void {
    const fifo_path = std.fmt.allocPrint(allocator, "{s}/{s}/exec.fifo", .{ root_dir, container_id }) catch return error.OutOfMemory;
    defer allocator.free(fifo_path);

    const file = std.fs.openFileAbsolute(fifo_path, .{ .mode = .write_only }) catch |err| {
        scoped_log.err("Cannot open FIFO for container {s}: {}", .{ container_id, err });
        return error.StartFailed;
    };
    defer file.close();
    file.writeAll("s") catch return error.StartFailed;

    scoped_log.info("Container {s} started", .{container_id});

    // Update state to running
    const state_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ root_dir, container_id }) catch return;
    defer allocator.free(state_path);

    // Read current state to get PID
    const state_file = std.fs.openFileAbsolute(state_path, .{}) catch return;
    defer state_file.close();
    var buf: [4096]u8 = undefined;
    const n = state_file.readAll(&buf) catch return;
    _ = n;

    // TODO: parse PID from state and update status to "running"
}

fn doContainerExec(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    argv: []const []const u8,
    env: ?[]const []const u8,
    cwd: []const u8,
) void {
    // Ensure rootfs is a mount point
    {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (rootfs_path.len < buf.len) {
            @memcpy(buf[0..rootfs_path.len], rootfs_path);
            buf[rootfs_path.len] = 0;
            const z: [*:0]const u8 = @ptrCast(buf[0..rootfs_path.len :0]);
            syscall.mount(z, z, null, .{ .bind = true }, null) catch {};
        }
    }

    // pivot_root
    const old_root = std.fmt.allocPrint(allocator, "{s}/mnt/oldroot", .{rootfs_path}) catch return;
    defer allocator.free(old_root);
    const rootfs_z = allocator.dupeZ(u8, rootfs_path) catch return;
    defer allocator.free(rootfs_z);
    const old_root_z = allocator.dupeZ(u8, old_root) catch return;
    defer allocator.free(old_root_z);

    syscall.pivotRoot(rootfs_z, old_root_z) catch {
        syscall.chroot(rootfs_z) catch return;
    };

    // chdir
    const cwd_z = allocator.dupeZ(u8, cwd) catch null;
    if (cwd_z) |z| {
        syscall.chdir(z) catch {};
        allocator.free(z);
    } else {
        syscall.chdir("/") catch {};
    }

    // Unmount old root
    mount_util.umountDetach("/mnt/oldroot") catch {};

    // Apply capabilities
    capabilities.setNoNewPrivs();

    // exec
    var c_argv: std.ArrayListUnmanaged(?[*:0]const u8) = .{};
    for (argv) |arg| {
        const z = allocator.dupeZ(u8, arg) catch return;
        c_argv.append(allocator, z) catch return;
    }
    c_argv.append(allocator, null) catch return;

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
    scoped_log.err("execve failed: {}", .{err});
}
