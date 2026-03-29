const std = @import("std");
const runz = @import("runz");

const container = runz.container;
const runtime_spec = runz.runtime_spec;
const cgroup = runz.linux_util.cgroup;

const version = "0.1.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = std.process.args();
    _ = args.next(); // skip argv[0]

    // Parse global options
    var root_dir: []const u8 = "/run/runz";
    var log_path: ?[]const u8 = null;
    var command: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--root")) {
            root_dir = args.next() orelse return fatal("--root requires a path");
        } else if (std.mem.eql(u8, arg, "--log")) {
            log_path = args.next() orelse return fatal("--log requires a path");
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            try std.fs.File.stdout().deprecatedWriter().print("runz version {s}\n", .{version});
            return;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            command = arg;
            break;
        } else {
            return fatal2("unknown option: {s}", .{arg});
        }
    }

    // TODO: redirect logs to log_path if set
    if (log_path) |_| {}

    const cmd = command orelse {
        printUsage();
        std.process.exit(1);
    };

    if (std.mem.eql(u8, cmd, "create")) {
        try cmdCreate(allocator, root_dir, &args);
    } else if (std.mem.eql(u8, cmd, "start")) {
        try cmdStart(allocator, root_dir, &args);
    } else if (std.mem.eql(u8, cmd, "kill")) {
        try cmdKill(allocator, root_dir, &args);
    } else if (std.mem.eql(u8, cmd, "delete")) {
        try cmdDelete(allocator, root_dir, &args);
    } else if (std.mem.eql(u8, cmd, "state")) {
        try cmdState(allocator, root_dir, &args);
    } else if (std.mem.eql(u8, cmd, "list")) {
        try cmdList(allocator, root_dir);
    } else if (std.mem.eql(u8, cmd, "exec")) {
        try cmdExec(allocator, root_dir, &args);
    } else if (std.mem.eql(u8, cmd, "run")) {
        try cmdRun(allocator, root_dir, &args);
    } else if (std.mem.eql(u8, cmd, "spec")) {
        try cmdSpec();
    } else {
        return fatal2("unknown command: {s}", .{cmd});
    }
}

// --- Commands ---

fn cmdRun(allocator: std.mem.Allocator, root_dir: []const u8, args: *std.process.ArgIterator) !void {
    var bundle: []const u8 = ".";
    var container_id: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-b") or std.mem.eql(u8, arg, "--bundle")) {
            bundle = args.next() orelse return fatal("--bundle requires a path");
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            if (container_id == null) {
                container_id = arg;
            }
        } else {
            return fatal2("run: unknown option: {s}", .{arg});
        }
    }

    const id = container_id orelse return fatal("run requires a container ID");

    const exit_code = runz.spec_run.runFromBundle(allocator, bundle, id, root_dir) catch |err| {
        return fatal2("run failed: {}", .{err});
    };

    if (exit_code != 0) {
        std.process.exit(exit_code);
    }
}

fn cmdCreate(allocator: std.mem.Allocator, root_dir: []const u8, args: *std.process.ArgIterator) !void {
    var bundle: []const u8 = ".";
    var container_id: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-b") or std.mem.eql(u8, arg, "--bundle")) {
            bundle = args.next() orelse return fatal("--bundle requires a path");
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            container_id = arg;
        } else {
            return fatal2("create: unknown option: {s}", .{arg});
        }
    }

    const id = container_id orelse return fatal("create requires a container ID");

    // Read config.json from bundle
    const config_path = try std.fmt.allocPrint(allocator, "{s}/config.json", .{bundle});
    defer allocator.free(config_path);

    _ = runtime_spec.parseConfigFile(allocator, config_path) catch |err| {
        return fatal2("cannot read config.json: {}", .{err});
    };

    var mgr = container.Manager.init(allocator, root_dir);
    var info = mgr.create(id, bundle, null) catch |err| {
        return fatal2("create failed: {}", .{err});
    };

    // TODO: fork container process, set up namespaces, pause on FIFO
    // For now, just create the state entry
    _ = &info;
}

fn cmdStart(allocator: std.mem.Allocator, root_dir: []const u8, args: *std.process.ArgIterator) !void {
    const id = args.next() orelse return fatal("start requires a container ID");
    _ = allocator;

    // TODO: signal the container's init process via FIFO to exec
    const fifo_path = std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}/exec.fifo", .{ root_dir, id }) catch return;
    defer std.heap.page_allocator.free(fifo_path);

    const file = std.fs.openFileAbsolute(fifo_path, .{ .mode = .write_only }) catch |err| {
        return fatal2("cannot signal container {s}: {}", .{ id, err });
    };
    defer file.close();
    file.writeAll("s") catch {};
}

fn cmdKill(allocator: std.mem.Allocator, root_dir: []const u8, args: *std.process.ArgIterator) !void {
    const id = args.next() orelse return fatal("kill requires a container ID");
    const sig_str = args.next() orelse "SIGTERM";

    const signal = parseSignal(sig_str);

    var mgr = container.Manager.init(allocator, root_dir);

    // Read state to get PID
    const state_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ root_dir, id }) catch return;
    defer allocator.free(state_path);

    const file = std.fs.openFileAbsolute(state_path, .{}) catch |err| {
        return fatal2("container {s} not found: {}", .{ id, err });
    };
    defer file.close();

    var buf: [4096]u8 = undefined;
    const n = file.readAll(&buf) catch return;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, buf[0..n], .{}) catch return;
    defer parsed.deinit();

    if (parsed.value.object.get("pid")) |pid_val| {
        if (pid_val == .integer) {
            const pid: i32 = @intCast(pid_val.integer);
            if (pid > 0) {
                _ = std.os.linux.kill(pid, signal);
            }
        }
    }

    _ = &mgr;
}

fn cmdDelete(allocator: std.mem.Allocator, root_dir: []const u8, args: *std.process.ArgIterator) !void {
    const id = args.next() orelse return fatal("delete requires a container ID");

    // Remove state file and container directory
    const state_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ root_dir, id }) catch return;
    defer allocator.free(state_path);
    std.fs.deleteFileAbsolute(state_path) catch {};

    const dir_path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ root_dir, id }) catch return;
    defer allocator.free(dir_path);
    std.fs.deleteTreeAbsolute(dir_path) catch {};
}

fn cmdState(allocator: std.mem.Allocator, root_dir: []const u8, args: *std.process.ArgIterator) !void {
    const id = args.next() orelse return fatal("state requires a container ID");

    const state_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ root_dir, id }) catch return;
    defer allocator.free(state_path);

    const file = std.fs.openFileAbsolute(state_path, .{}) catch |err| {
        return fatal2("container {s} not found: {}", .{ id, err });
    };
    defer file.close();

    var buf: [4096]u8 = undefined;
    const n = file.readAll(&buf) catch return;

    const stdout = std.fs.File.stdout().deprecatedWriter();
    try stdout.writeAll(buf[0..n]);
    try stdout.writeAll("\n");
}

fn cmdList(allocator: std.mem.Allocator, root_dir: []const u8) !void {
    var mgr = container.Manager.init(allocator, root_dir);
    const ids = try mgr.list(allocator);
    defer {
        for (ids) |id| allocator.free(id);
        allocator.free(ids);
    }

    const stdout = std.fs.File.stdout().deprecatedWriter();
    try stdout.writeAll("ID\tSTATUS\tPID\tBUNDLE\n");
    for (ids) |id| {
        const state_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ root_dir, id }) catch continue;
        defer allocator.free(state_path);

        const file = std.fs.openFileAbsolute(state_path, .{}) catch continue;
        defer file.close();
        var buf: [4096]u8 = undefined;
        const n = file.readAll(&buf) catch continue;
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, buf[0..n], .{}) catch continue;
        defer parsed.deinit();

        const status = if (parsed.value.object.get("status")) |s| (if (s == .string) s.string else "unknown") else "unknown";
        const pid = if (parsed.value.object.get("pid")) |p| (if (p == .integer) p.integer else 0) else 0;
        const bun = if (parsed.value.object.get("bundle")) |b| (if (b == .string) b.string else "") else "";

        try stdout.print("{s}\t{s}\t{d}\t{s}\n", .{ id, status, pid, bun });
    }
}

fn cmdExec(allocator: std.mem.Allocator, root_dir: []const u8, args: *std.process.ArgIterator) !void {
    const id = args.next() orelse return fatal("exec requires a container ID");

    // Collect remaining args as the command
    var cmd_args: std.ArrayListUnmanaged([]const u8) = .{};
    defer cmd_args.deinit(allocator);
    while (args.next()) |arg| {
        try cmd_args.append(allocator, arg);
    }
    if (cmd_args.items.len == 0) return fatal("exec requires a command");

    // Read state to get PID
    const state_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ root_dir, id }) catch return;
    defer allocator.free(state_path);

    const file = std.fs.openFileAbsolute(state_path, .{}) catch |err| {
        return fatal2("container {s} not found: {}", .{ id, err });
    };
    defer file.close();

    var buf: [4096]u8 = undefined;
    const n = file.readAll(&buf) catch return;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, buf[0..n], .{}) catch return;
    defer parsed.deinit();

    const pid: i32 = if (parsed.value.object.get("pid")) |p| (if (p == .integer) @intCast(p.integer) else return fatal("container has no PID")) else return fatal("container has no PID");

    try runz.exec.execInContainer(allocator, pid, cmd_args.items, null);
}

fn cmdSpec() !void {
    const stdout = std.fs.File.stdout().deprecatedWriter();
    try stdout.writeAll(default_spec);
    try stdout.writeAll("\n");
}

// --- Helpers ---

fn fatal(msg: []const u8) void {
    std.debug.print("runz: {s}\n", .{msg});
    std.process.exit(1);
}

fn fatal2(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("runz: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn parseSignal(name: []const u8) i32 {
    const linux = std.os.linux;
    if (std.mem.eql(u8, name, "SIGTERM") or std.mem.eql(u8, name, "TERM") or std.mem.eql(u8, name, "15")) return linux.SIG.TERM;
    if (std.mem.eql(u8, name, "SIGKILL") or std.mem.eql(u8, name, "KILL") or std.mem.eql(u8, name, "9")) return linux.SIG.KILL;
    if (std.mem.eql(u8, name, "SIGINT") or std.mem.eql(u8, name, "INT") or std.mem.eql(u8, name, "2")) return linux.SIG.INT;
    if (std.mem.eql(u8, name, "SIGHUP") or std.mem.eql(u8, name, "HUP") or std.mem.eql(u8, name, "1")) return linux.SIG.HUP;
    if (std.mem.eql(u8, name, "SIGUSR1") or std.mem.eql(u8, name, "USR1") or std.mem.eql(u8, name, "10")) return linux.SIG.USR1;
    if (std.mem.eql(u8, name, "SIGUSR2") or std.mem.eql(u8, name, "USR2") or std.mem.eql(u8, name, "12")) return linux.SIG.USR2;
    return std.fmt.parseInt(i32, name, 10) catch linux.SIG.TERM;
}

fn printUsage() void {
    std.debug.print(
        \\runz - OCI container runtime
        \\
        \\Usage: runz [global-options] <command> [args]
        \\
        \\Commands:
        \\  run <id> -b <bundle>     Create and start a container
        \\  create <id> -b <bundle>  Create a container (paused)
        \\  start <id>               Start a created container
        \\  kill <id> [signal]       Send signal to container (default: SIGTERM)
        \\  delete <id>              Delete a stopped container
        \\  state <id>               Query container state (JSON)
        \\  list                     List containers
        \\  exec <id> <cmd...>       Execute a process in a running container
        \\  spec                     Print default OCI config.json
        \\
        \\Global options:
        \\  --root <path>            State directory (default: /run/runz)
        \\  --log <path>             Log file path
        \\  -v, --version            Print version
        \\  -h, --help               Print this help
        \\
    , .{});
}

const default_spec =
    \\{
    \\  "ociVersion": "1.0.2",
    \\  "process": {
    \\    "terminal": true,
    \\    "user": {"uid": 0, "gid": 0},
    \\    "args": ["sh"],
    \\    "env": [
    \\      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    \\      "TERM=xterm"
    \\    ],
    \\    "cwd": "/",
    \\    "capabilities": {
    \\      "bounding": ["CAP_AUDIT_WRITE","CAP_KILL","CAP_NET_BIND_SERVICE"],
    \\      "effective": ["CAP_AUDIT_WRITE","CAP_KILL","CAP_NET_BIND_SERVICE"],
    \\      "permitted": ["CAP_AUDIT_WRITE","CAP_KILL","CAP_NET_BIND_SERVICE"],
    \\      "ambient": ["CAP_AUDIT_WRITE","CAP_KILL","CAP_NET_BIND_SERVICE"]
    \\    },
    \\    "noNewPrivileges": true
    \\  },
    \\  "root": {"path": "rootfs", "readonly": true},
    \\  "hostname": "runz",
    \\  "mounts": [
    \\    {"destination": "/proc", "type": "proc", "source": "proc"},
    \\    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","strictatime","mode=755","size=65536k"]},
    \\    {"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620"]},
    \\    {"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid","noexec","nodev","mode=1777","size=65536k"]},
    \\    {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid","noexec","nodev","ro"]}
    \\  ],
    \\  "linux": {
    \\    "namespaces": [
    \\      {"type": "pid"},
    \\      {"type": "network"},
    \\      {"type": "ipc"},
    \\      {"type": "uts"},
    \\      {"type": "mount"}
    \\    ],
    \\    "maskedPaths": ["/proc/asound","/proc/acpi","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware"],
    \\    "readonlyPaths": ["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]
    \\  }
    \\}
;
