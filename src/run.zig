const std = @import("std");
const linux = std.os.linux;
const log = @import("log.zig");
const syscall = @import("linux/syscall.zig");
const mount_util = @import("linux/mount.zig");
const seccomp = @import("linux/seccomp.zig");
const namespace = @import("linux/namespace.zig");
const dev = @import("linux/dev.zig");

const veth = @import("linux/veth.zig");
const netlink = @import("linux/netlink.zig");

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

pub const NetworkMode = enum {
    /// Isolated network namespace with veth pair + NAT (default)
    veth,
    /// Share host network namespace
    host,
    /// Isolated network namespace with no connectivity
    none,
};

pub const ContainerOptions = struct {
    /// Environment variables (null = default PATH/HOME/TERM)
    env: ?[]const []const u8 = null,
    /// Network mode
    network: NetworkMode = .veth,
    /// Run rootless (user namespace with uid/gid mapping)
    rootless: bool = false,
    /// Resource limits (null = no cgroup)
    resources: ?*const @import("linux/cgroup.zig").Resources = null,
    /// OCI spec mounts (null = use default mounts)
    mounts: ?[]const @import("runtime_spec.zig").Mount = null,
    /// Capabilities to apply (null = keep all)
    capabilities: ?@import("linux/capabilities.zig").CapSet = null,
    /// Working directory (null = /)
    cwd: ?[]const u8 = null,
};

/// Execute a short-lived command inside a rootfs with container isolation.
/// Sets up namespaces, mounts, seccomp, and minimal /dev.
pub fn executeInRootfs(
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

/// Run a long-lived container: sets up mount+PID namespaces, pivot_root into
/// the rootfs, and execs the entrypoint. The parent waits for the child.
/// Unlike executeInRootfs (designed for short RUN commands), this uses
/// pivot_root for a proper rootfs swap and binds /dev from the host
/// (including /dev/net/tun for VPN/WireGuard).
pub fn runContainer(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    argv: []const []const u8,
    options: ContainerOptions,
) RunError!u8 {
    if (argv.len == 0) return 0;

    scoped_log.info("Starting container: {s} (network={s})", .{ argv[0], @tagName(options.network) });

    const host_veth_name = "veth-oci-h";
    const guest_veth_name = "veth-oci-g";

    // For veth mode: create the pair before forking (in host netns)
    if (options.network == .veth) {
        veth.createVethPair(host_veth_name, guest_veth_name) catch |err| {
            scoped_log.warn("Failed to create veth pair: {}, falling back to host networking", .{err});
            var fallback = options;
            fallback.network = .host;
            return runContainer(allocator, rootfs_path, argv, fallback);
        };
    }

    const use_veth = options.network == .veth;
    // Sync pipes needed for veth (network setup) or rootless (uid/gid map writing)
    const need_sync = use_veth or options.rootless;
    const pipe_to_parent = if (need_sync) std.posix.pipe() catch return error.SetupFailed else .{ @as(std.posix.fd_t, -1), @as(std.posix.fd_t, -1) };
    const pipe_to_child = if (need_sync) std.posix.pipe() catch return error.SetupFailed else .{ @as(std.posix.fd_t, -1), @as(std.posix.fd_t, -1) };

    // Save caller's UID/GID before forking (needed for rootless uid/gid maps)
    const outer_uid = linux.getuid();
    const outer_gid = linux.getgid();

    const fork_result = doFork();
    if (fork_result == null) {
        scoped_log.err("fork failed", .{});
        return error.CommandFailed;
    }

    const child_pid = fork_result.?;

    if (child_pid == 0) {
        // === CHILD ===
        if (pipe_to_parent[0] != -1) std.posix.close(pipe_to_parent[0]); // close read end
        if (pipe_to_child[1] != -1) std.posix.close(pipe_to_child[1]); // close write end

        // Rootless: unshare user namespace first (before other namespaces)
        if (options.rootless) {
            syscall.unshareRaw(syscall.CloneFlags.CLONE_NEWUSER) catch |err| {
                scoped_log.err("Failed to unshare user namespace: {}", .{err});
                std.process.exit(126);
            };
        }

        // Unshare mount + PID + optionally network
        var ns_flags: u32 = syscall.CloneFlags.CLONE_NEWNS | syscall.CloneFlags.CLONE_NEWPID;
        if (options.network != .host) {
            ns_flags |= syscall.CloneFlags.CLONE_NEWNET;
        }
        syscall.unshareRaw(ns_flags) catch |err| {
            scoped_log.err("Failed to unshare namespaces: {}", .{err});
            std.process.exit(126);
        };

        if (need_sync) {
            // Signal parent: "I've unshared"
            _ = std.posix.write(pipe_to_parent[1], "r") catch {};
            std.posix.close(pipe_to_parent[1]);

            // Wait for parent to finish setup (uid/gid maps + network)
            var wait_buf: [1]u8 = undefined;
            _ = std.posix.read(pipe_to_child[0], &wait_buf) catch {};
            std.posix.close(pipe_to_child[0]);

            // Configure guest networking
            veth.setLoopbackUp() catch {};
            veth.setUp(guest_veth_name) catch {};
            veth.addAddress(guest_veth_name, netlink.ipv4(10, 200, 0, 2), 24) catch {};
            veth.addDefaultRoute(netlink.ipv4(10, 200, 0, 1), guest_veth_name) catch {};
        }

        // Make root private to prevent mount propagation
        syscall.mount(null, "/", null, .{ .private = true, .rec = true }, null) catch {};

        // Setup mounts in rootfs
        setupContainerMounts(allocator, rootfs_path) catch |err| {
            scoped_log.warn("Container mount setup failed: {}", .{err});
        };

        // Copy DNS config
        setupDns(allocator, rootfs_path) catch {};

        // Double-fork for PID namespace (grandchild becomes PID 1)
        const inner_result = doFork();
        if (inner_result == null) {
            scoped_log.err("inner fork failed", .{});
            std.process.exit(126);
        }

        const grandchild_pid = inner_result.?;
        if (grandchild_pid == 0) {
            pivotAndExec(allocator, rootfs_path, argv, &options);
            std.process.exit(127);
        }

        const status = waitForChild(grandchild_pid);
        std.process.exit(status);
    }

    // === PARENT ===
    if (pipe_to_parent[1] != -1) std.posix.close(pipe_to_parent[1]); // close write end
    if (pipe_to_child[0] != -1) std.posix.close(pipe_to_child[0]); // close read end

    if (need_sync) {
        // Wait for child to signal it has unshared namespaces
        var ready_buf: [1]u8 = undefined;
        _ = std.posix.read(pipe_to_parent[0], &ready_buf) catch {};
        std.posix.close(pipe_to_parent[0]);

        // Rootless: write uid/gid maps for the child
        if (options.rootless) {
            namespace.writeUidMapRootless(child_pid, allocator) catch |err| {
                scoped_log.warn("Failed to write uid_map: {}", .{err});
                namespace.writeUidMap(child_pid, outer_uid) catch {};
            };
            namespace.writeGidMapRootless(child_pid, allocator) catch |err| {
                scoped_log.warn("Failed to write gid_map: {}", .{err});
                namespace.writeGidMap(child_pid, outer_gid) catch {};
            };
        }
    }

    if (use_veth) {
        // Move guest veth into child's network namespace
        veth.moveToNamespace(guest_veth_name, child_pid) catch |err| {
            scoped_log.warn("Failed to move veth to child ns: {}", .{err});
        };

        // Configure host side
        veth.addAddress(host_veth_name, netlink.ipv4(10, 200, 0, 1), 24) catch |err| {
            scoped_log.warn("Failed to configure host veth: {}", .{err});
        };
        veth.setUp(host_veth_name) catch |err| {
            scoped_log.warn("Failed to bring up host veth: {}", .{err});
        };

        // Enable forwarding + NAT
        veth.enableIpForwarding() catch {};
        veth.setupMasquerade() catch |err| {
            scoped_log.warn("Failed to setup NAT: {}", .{err});
        };
    }

    if (need_sync) {
        // Signal child: "parent setup complete"
        _ = std.posix.write(pipe_to_child[1], "g") catch {};
        std.posix.close(pipe_to_child[1]);
    }

    const exit_code = waitForChild(child_pid);

    // Cleanup (veth is auto-destroyed when namespace dies, but clean up NAT)
    if (options.network == .veth) {
        veth.deleteInterface(host_veth_name);
        veth.teardownMasquerade();
    }

    return exit_code;
}

/// Set up mounts for a container: bind /dev from host (for device access),
/// mount proc, sysfs, tmpfs on /tmp, and ensure /dev/net/tun exists.
pub fn setupContainerMountsPublic(allocator: std.mem.Allocator, rootfs_path: []const u8) void {
    setupContainerMounts(allocator, rootfs_path) catch {};
}

fn setupContainerMounts(allocator: std.mem.Allocator, rootfs_path: []const u8) !void {
    {
        var dir = std.fs.openDirAbsolute(rootfs_path, .{}) catch return error.SetupFailed;
        defer dir.close();
        dir.makePath("proc") catch {};
        dir.makePath("dev") catch {};
        dir.makePath("dev/net") catch {};
        dir.makePath("sys") catch {};
        dir.makePath("etc") catch {};
        dir.makePath("tmp") catch {};
        dir.makePath("run") catch {};
        dir.makePath("mnt/oldroot") catch {};
    }

    // Bind mount /dev from host (recursive — gets /dev/pts, /dev/shm, etc.)
    {
        const dev_path = std.fmt.allocPrint(allocator, "{s}/dev", .{rootfs_path}) catch return error.OutOfMemory;
        defer allocator.free(dev_path);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (dev_path.len < buf.len) {
            @memcpy(buf[0..dev_path.len], dev_path);
            buf[dev_path.len] = 0;
            const z: [*:0]const u8 = @ptrCast(buf[0..dev_path.len :0]);
            syscall.mount("/dev", z, null, .{ .bind = true, .rec = true }, null) catch |err| {
                scoped_log.warn("Failed to bind mount /dev: {}", .{err});
            };
        }
    }

    // Mount proc
    {
        const path = std.fmt.allocPrint(allocator, "{s}/proc", .{rootfs_path}) catch return error.OutOfMemory;
        defer allocator.free(path);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (path.len < buf.len) {
            @memcpy(buf[0..path.len], path);
            buf[path.len] = 0;
            const z: [*:0]const u8 = @ptrCast(buf[0..path.len :0]);
            syscall.mount("proc", z, "proc", .{ .nosuid = true, .noexec = true, .nodev = true }, null) catch {};
        }
    }

    // Bind mount /sys
    {
        const path = std.fmt.allocPrint(allocator, "{s}/sys", .{rootfs_path}) catch return error.OutOfMemory;
        defer allocator.free(path);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (path.len < buf.len) {
            @memcpy(buf[0..path.len], path);
            buf[path.len] = 0;
            const z: [*:0]const u8 = @ptrCast(buf[0..path.len :0]);
            syscall.mount("/sys", z, null, .{ .bind = true, .rec = true }, null) catch {
                syscall.mount("sysfs", z, "sysfs", .{ .rdonly = true, .nosuid = true, .noexec = true, .nodev = true }, null) catch {};
            };
        }
    }

    // Mount tmpfs on /tmp
    {
        const path = std.fmt.allocPrint(allocator, "{s}/tmp", .{rootfs_path}) catch return error.OutOfMemory;
        defer allocator.free(path);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (path.len < buf.len) {
            @memcpy(buf[0..path.len], path);
            buf[path.len] = 0;
            const z: [*:0]const u8 = @ptrCast(buf[0..path.len :0]);
            syscall.mount("tmpfs", z, "tmpfs", .{ .nosuid = true, .nodev = true }, @ptrCast("size=65536k,mode=1777")) catch {};
        }
    }

    // Bind mount /run for runtime state
    {
        const path = std.fmt.allocPrint(allocator, "{s}/run", .{rootfs_path}) catch return error.OutOfMemory;
        defer allocator.free(path);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (path.len < buf.len) {
            @memcpy(buf[0..path.len], path);
            buf[path.len] = 0;
            const z: [*:0]const u8 = @ptrCast(buf[0..path.len :0]);
            syscall.mount("tmpfs", z, "tmpfs", .{ .nosuid = true, .nodev = true }, @ptrCast("size=65536k,mode=755")) catch {};
        }
    }
}

/// pivot_root into rootfs and exec the command
fn pivotAndExec(
    allocator: std.mem.Allocator,
    rootfs_path: []const u8,
    argv: []const []const u8,
    options: *const ContainerOptions,
) void {
    const spec_mount = @import("spec_mount.zig");
    const caps = @import("linux/capabilities.zig");

    // Ensure rootfs is a mount point (required by pivot_root)
    {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (rootfs_path.len < buf.len) {
            @memcpy(buf[0..rootfs_path.len], rootfs_path);
            buf[rootfs_path.len] = 0;
            const z: [*:0]const u8 = @ptrCast(buf[0..rootfs_path.len :0]);
            syscall.mount(z, z, null, .{ .bind = true }, null) catch {};
        }
    }

    // Apply OCI spec mounts before pivot (they target paths inside rootfs)
    if (options.mounts) |mounts| {
        spec_mount.applySpecMounts(allocator, rootfs_path, mounts);
    }

    // pivot_root
    const old_root = std.fmt.allocPrint(allocator, "{s}/mnt/oldroot", .{rootfs_path}) catch return;
    defer allocator.free(old_root);

    const rootfs_z = allocator.dupeZ(u8, rootfs_path) catch return;
    defer allocator.free(rootfs_z);
    const old_root_z = allocator.dupeZ(u8, old_root) catch return;
    defer allocator.free(old_root_z);

    syscall.pivotRoot(rootfs_z, old_root_z) catch |err| {
        scoped_log.err("pivot_root failed: {}, falling back to chroot", .{err});
        syscall.chroot(rootfs_z) catch return;
        syscall.chdir("/") catch return;
        applyPreExec(options, caps);
        doExec(allocator, argv, options.env);
        return;
    };

    // Change to working directory
    const cwd_z = if (options.cwd) |cwd| (allocator.dupeZ(u8, cwd) catch null) else null;
    if (cwd_z) |z| {
        syscall.chdir(z) catch {};
        allocator.free(z);
    } else {
        syscall.chdir("/") catch return;
    }

    // Unmount old root (lazy)
    mount_util.umountDetach("/mnt/oldroot") catch {};

    // Apply capabilities and security settings before exec
    applyPreExec(options, caps);

    doExec(allocator, argv, options.env);
}

/// Apply capabilities and no_new_privs before exec
fn applyPreExec(options: *const ContainerOptions, caps_mod: anytype) void {
    // Apply capabilities if specified
    if (options.capabilities) |cap_set| {
        caps_mod.applyCaps(cap_set) catch {};
    }
    // Set no_new_privs (default for OCI containers)
    caps_mod.setNoNewPrivs();
}

/// Build argv/envp and exec
fn doExec(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    env: ?[]const []const u8,
) void {
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
        std.debug.print("runz: chroot failed\n", .{});
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
    std.debug.print("runz: execve failed: {}\n", .{err});
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
        std.debug.print("runz: chroot failed\n", .{});
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
    std.debug.print("runz: execve failed: {}\n", .{err});
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
        _ = linux.syscall2(.umount2, @intFromPtr(path_z.ptr), MNT_DETACH);
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
