const std = @import("std");
const linux = std.os.linux;
const log = @import("log.zig");
const syscall = @import("linux/syscall.zig");
const capabilities = @import("linux/capabilities.zig");

const scoped_log = log.scoped("exec");

pub const ExecError = error{
    ContainerNotRunning,
    NamespaceEntryFailed,
    ForkFailed,
    ExecFailed,
    OutOfMemory,
};

/// Execute a process inside a running container's namespaces.
/// Uses setns to enter the container's mount, PID, network, etc. namespaces,
/// then forks and execs the command.
pub fn execInContainer(
    allocator: std.mem.Allocator,
    container_pid: i32,
    argv: []const []const u8,
    env: ?[]const []const u8,
) ExecError!void {
    if (argv.len == 0) return;

    scoped_log.info("exec in container (pid={d}): {s}", .{ container_pid, argv[0] });

    // Verify the container process is alive
    const kill_rc = linux.kill(container_pid, 0);
    if (linux.E.init(kill_rc) != .SUCCESS) {
        return error.ContainerNotRunning;
    }

    // Open namespace file descriptors
    const ns_types = [_]struct { name: []const u8, flag: u32 }{
        .{ .name = "user", .flag = 0x10000000 }, // CLONE_NEWUSER
        .{ .name = "mnt", .flag = 0x00020000 }, // CLONE_NEWNS
        .{ .name = "pid", .flag = 0x20000000 }, // CLONE_NEWPID
        .{ .name = "net", .flag = 0x40000000 }, // CLONE_NEWNET
        .{ .name = "uts", .flag = 0x04000000 }, // CLONE_NEWUTS
        .{ .name = "ipc", .flag = 0x08000000 }, // CLONE_NEWIPC
        .{ .name = "cgroup", .flag = 0x02000000 }, // CLONE_NEWCGROUP
    };

    var ns_fds: [ns_types.len]i32 = .{-1} ** ns_types.len;
    defer for (&ns_fds) |*fd| {
        if (fd.* >= 0) std.posix.close(@intCast(@as(u32, @bitCast(fd.*))));
    };

    // Open each namespace fd
    for (ns_types, 0..) |ns, i| {
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/ns/{s}", .{ container_pid, ns.name }) catch continue;
        const path_z = std.posix.toPosixPath(path) catch continue;

        const fd = linux.openat(
            linux.AT.FDCWD,
            &path_z,
            .{ .CLOEXEC = true },
            0,
        );
        if (linux.E.init(fd) == .SUCCESS) {
            ns_fds[i] = @intCast(fd);
        }
    }

    // Enter each namespace via setns
    for (ns_types, 0..) |ns, i| {
        if (ns_fds[i] < 0) continue;
        const rc = linux.syscall2(.setns, @as(u32, @bitCast(ns_fds[i])), ns.flag);
        if (linux.E.init(rc) != .SUCCESS) {
            scoped_log.debug("setns({s}) failed", .{ns.name});
        }
    }

    // Fork — child will be in the new PID namespace
    const fork_rc = if (@hasField(linux.SYS, "fork"))
        linux.syscall0(.fork)
    else
        linux.syscall5(.clone, linux.SIG.CHLD, 0, 0, 0, 0);

    if (linux.E.init(fork_rc) != .SUCCESS) {
        return error.ForkFailed;
    }

    if (fork_rc == 0) {
        // Child: exec the command
        doExec(allocator, argv, env);
        std.process.exit(127);
    }

    // Join the container's cgroup
    {
        const child_pid: i32 = @bitCast(@as(u32, @truncate(fork_rc)));
        const cg_path = getContainerCgroupPath(allocator, container_pid);
        if (cg_path) |path| {
            defer allocator.free(path);
            var procs_buf: [std.fs.max_path_bytes]u8 = undefined;
            const procs_path = std.fmt.bufPrint(&procs_buf, "{s}/cgroup.procs", .{path}) catch null;
            if (procs_path) |pp| {
                const f = std.fs.openFileAbsolute(pp, .{ .mode = .write_only }) catch null;
                if (f) |file| {
                    defer file.close();
                    var pid_buf: [32]u8 = undefined;
                    const pid_str = std.fmt.bufPrint(&pid_buf, "{d}", .{child_pid}) catch "";
                    file.writeAll(pid_str) catch {};
                }
            }
        }
    }

    // Parent: wait for child
    var status: u32 = 0;
    while (true) {
        const wait_rc = linux.syscall4(
            .wait4,
            fork_rc,
            @intFromPtr(&status),
            0,
            0,
        );
        if (linux.E.init(wait_rc) == .INTR) continue;
        break;
    }

    const exit_code: u8 = @intCast((status >> 8) & 0xFF);
    if (exit_code != 0) {
        std.process.exit(exit_code);
    }
}

fn doExec(allocator: std.mem.Allocator, argv: []const []const u8, env: ?[]const []const u8) void {
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
        // Inherit from current process via libc
        const envp = std.c.environ;
        var i: usize = 0;
        while (envp[i]) |e| : (i += 1) {
            c_envp.append(allocator, e) catch return;
        }
    }
    c_envp.append(allocator, null) catch return;

    const cmd_z = allocator.dupeZ(u8, argv[0]) catch return;
    const err = std.posix.execveZ(cmd_z, @ptrCast(c_argv.items.ptr), @ptrCast(c_envp.items.ptr));
    scoped_log.err("execve failed: {}", .{err});
}

/// Get the cgroup path for a container process by reading /proc/<pid>/cgroup
fn getContainerCgroupPath(allocator: std.mem.Allocator, pid: i32) ?[]const u8 {
    var path_buf: [64]u8 = undefined;
    const proc_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/cgroup", .{pid}) catch return null;
    const file = std.fs.openFileAbsolute(proc_path, .{}) catch return null;
    defer file.close();

    var buf: [4096]u8 = undefined;
    const n = file.readAll(&buf) catch return null;

    // cgroup v2: line starts with "0::" followed by path
    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "0::")) {
            const suffix = line[3..];
            return std.fmt.allocPrint(allocator, "/sys/fs/cgroup{s}", .{suffix}) catch null;
        }
    }
    return null;
}

test "ExecError type" {
    const err: ExecError = error.ContainerNotRunning;
    _ = err;
}
