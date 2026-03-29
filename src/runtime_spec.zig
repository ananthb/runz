const std = @import("std");
const log = @import("log.zig");

const scoped_log = log.scoped("runtime-spec");

/// OCI Runtime Spec config.json
/// See: https://github.com/opencontainers/runtime-spec/blob/main/config.md
pub const Spec = struct {
    ociVersion: []const u8 = "1.0.2",
    root: ?Root = null,
    process: ?Process = null,
    hostname: ?[]const u8 = null,
    mounts: ?[]const Mount = null,
    linux: ?Linux = null,

    pub fn deinit(self: *Spec, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }
};

pub const Root = struct {
    path: []const u8,
    readonly: bool = false,
};

pub const Process = struct {
    terminal: bool = false,
    cwd: []const u8 = "/",
    args: ?[]const []const u8 = null,
    env: ?[]const []const u8 = null,
    user: ?User = null,
    capabilities: ?Capabilities = null,
    noNewPrivileges: bool = true,
    rlimits: ?[]const Rlimit = null,
};

pub const User = struct {
    uid: u32 = 0,
    gid: u32 = 0,
    additionalGids: ?[]const u32 = null,
};

pub const Capabilities = struct {
    bounding: ?[]const []const u8 = null,
    effective: ?[]const []const u8 = null,
    inheritable: ?[]const []const u8 = null,
    permitted: ?[]const []const u8 = null,
    ambient: ?[]const []const u8 = null,
};

pub const Rlimit = struct {
    type: []const u8,
    hard: u64,
    soft: u64,
};

pub const Mount = struct {
    destination: []const u8,
    type: ?[]const u8 = null,
    source: ?[]const u8 = null,
    options: ?[]const []const u8 = null,
};

pub const Linux = struct {
    namespaces: ?[]const Namespace = null,
    resources: ?LinuxResources = null,
    seccomp: ?Seccomp = null,
    maskedPaths: ?[]const []const u8 = null,
    readonlyPaths: ?[]const []const u8 = null,
    cgroupsPath: ?[]const u8 = null,
};

pub const Namespace = struct {
    type: []const u8,
    path: ?[]const u8 = null,
};

pub const LinuxResources = struct {
    memory: ?MemoryResources = null,
    cpu: ?CpuResources = null,
    pids: ?PidsResources = null,
};

pub const MemoryResources = struct {
    limit: ?i64 = null,
    swap: ?i64 = null,
};

pub const CpuResources = struct {
    shares: ?u64 = null,
    quota: ?i64 = null,
    period: ?u64 = null,
    cpus: ?[]const u8 = null,
};

pub const PidsResources = struct {
    limit: i64 = -1,
};

pub const Seccomp = struct {
    /// Always allocated when parsed from JSON. Callers must free.
    defaultAction: []const u8,
    architectures: ?[]const []const u8 = null,
    syscalls: ?[]const SyscallRule = null,
};

pub const SyscallRule = struct {
    names: []const []const u8,
    action: []const u8,
};

/// Parse an OCI runtime spec config.json from a file
pub fn parseConfigFile(allocator: std.mem.Allocator, path: []const u8) !Spec {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    const stat = try file.stat();
    const data = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(data);
    _ = try file.readAll(data);

    return parseConfig(allocator, data);
}

/// Parse an OCI runtime spec config.json from bytes
pub fn parseConfig(allocator: std.mem.Allocator, data: []const u8) !Spec {
    return parseConfigManual(allocator, data);
}

/// Manual JSON parsing for more control over memory management
fn parseConfigManual(allocator: std.mem.Allocator, data: []const u8) !Spec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();

    const root = parsed.value;
    var spec = Spec{};

    if (root.object.get("ociVersion")) |v| {
        if (v == .string) spec.ociVersion = try allocator.dupe(u8, v.string);
    }

    if (root.object.get("hostname")) |v| {
        if (v == .string) spec.hostname = try allocator.dupe(u8, v.string);
    }

    if (root.object.get("root")) |r| {
        if (r.object.get("path")) |p| {
            if (p == .string) {
                spec.root = .{
                    .path = try allocator.dupe(u8, p.string),
                    .readonly = if (r.object.get("readonly")) |ro| (ro == .bool and ro.bool) else false,
                };
            }
        }
    }

    if (root.object.get("process")) |p| {
        spec.process = .{
            .terminal = if (p.object.get("terminal")) |t| (t == .bool and t.bool) else false,
            .cwd = if (p.object.get("cwd")) |c| blk: {
                if (c == .string) break :blk try allocator.dupe(u8, c.string);
                break :blk "/";
            } else "/",
            .args = if (p.object.get("args")) |a| try parseStringArray(allocator, a) else null,
            .env = if (p.object.get("env")) |e| try parseStringArray(allocator, e) else null,
            .noNewPrivileges = if (p.object.get("noNewPrivileges")) |n| (n == .bool and n.bool) else true,
            .user = if (p.object.get("user")) |u| User{
                .uid = if (u.object.get("uid")) |uid| (if (uid == .integer) @intCast(uid.integer) else 0) else 0,
                .gid = if (u.object.get("gid")) |gid| (if (gid == .integer) @intCast(gid.integer) else 0) else 0,
            } else null,
            .capabilities = if (p.object.get("capabilities")) |caps_obj| Capabilities{
                .bounding = if (caps_obj.object.get("bounding")) |b| try parseStringArray(allocator, b) else null,
                .effective = if (caps_obj.object.get("effective")) |e| try parseStringArray(allocator, e) else null,
                .inheritable = if (caps_obj.object.get("inheritable")) |i| try parseStringArray(allocator, i) else null,
                .permitted = if (caps_obj.object.get("permitted")) |pp| try parseStringArray(allocator, pp) else null,
                .ambient = if (caps_obj.object.get("ambient")) |a| try parseStringArray(allocator, a) else null,
            } else null,
        };
    }

    // Parse mounts
    if (root.object.get("mounts")) |mounts_val| {
        if (mounts_val == .array) {
            var mounts_list: std.ArrayListUnmanaged(Mount) = .{};
            for (mounts_val.array.items) |m| {
                if (m != .object) continue;
                const dest = m.object.get("destination") orelse continue;
                if (dest != .string) continue;

                var mount = Mount{
                    .destination = try allocator.dupe(u8, dest.string),
                };

                if (m.object.get("type")) |t| {
                    if (t == .string) mount.type = try allocator.dupe(u8, t.string);
                }
                if (m.object.get("source")) |s| {
                    if (s == .string) mount.source = try allocator.dupe(u8, s.string);
                }
                if (m.object.get("options")) |opts| {
                    mount.options = try parseStringArray(allocator, opts);
                }

                try mounts_list.append(allocator, mount);
            }
            if (mounts_list.items.len > 0) {
                spec.mounts = try mounts_list.toOwnedSlice(allocator);
            }
        }
    }

    // Parse linux.namespaces
    if (root.object.get("linux")) |lnx| {
        var linux_spec = Linux{};
        if (lnx.object.get("namespaces")) |ns_val| {
            if (ns_val == .array) {
                var ns_list: std.ArrayListUnmanaged(Namespace) = .{};
                for (ns_val.array.items) |ns| {
                    if (ns != .object) continue;
                    const ns_type = ns.object.get("type") orelse continue;
                    if (ns_type != .string) continue;
                    var namespace = Namespace{ .type = try allocator.dupe(u8, ns_type.string) };
                    if (ns.object.get("path")) |p| {
                        if (p == .string) namespace.path = try allocator.dupe(u8, p.string);
                    }
                    try ns_list.append(allocator, namespace);
                }
                if (ns_list.items.len > 0) linux_spec.namespaces = try ns_list.toOwnedSlice(allocator);
            }
        }
        if (lnx.object.get("maskedPaths")) |mp| {
            linux_spec.maskedPaths = try parseStringArray(allocator, mp);
        }
        if (lnx.object.get("readonlyPaths")) |rp| {
            linux_spec.readonlyPaths = try parseStringArray(allocator, rp);
        }
        if (lnx.object.get("cgroupsPath")) |cp| {
            if (cp == .string) linux_spec.cgroupsPath = try allocator.dupe(u8, cp.string);
        }
        // Parse seccomp
        if (lnx.object.get("seccomp")) |sec| {
            const default_action = if (sec.object.get("defaultAction")) |da|
                (if (da == .string) try allocator.dupe(u8, da.string) else try allocator.dupe(u8, "SCMP_ACT_ERRNO"))
            else
                try allocator.dupe(u8, "SCMP_ACT_ERRNO");
            var seccomp_spec = Seccomp{ .defaultAction = default_action };
            if (sec.object.get("architectures")) |arches| {
                seccomp_spec.architectures = try parseStringArray(allocator, arches);
            }
            if (sec.object.get("syscalls")) |sc_arr| {
                if (sc_arr == .array) {
                    var rules: std.ArrayListUnmanaged(SyscallRule) = .{};
                    for (sc_arr.array.items) |sc| {
                        if (sc != .object) continue;
                        const action_val = sc.object.get("action") orelse continue;
                        if (action_val != .string) continue;
                        const names_val = sc.object.get("names") orelse continue;
                        const names = try parseStringArray(allocator, names_val);
                        try rules.append(allocator, .{
                            .names = names,
                            .action = try allocator.dupe(u8, action_val.string),
                        });
                    }
                    if (rules.items.len > 0) seccomp_spec.syscalls = try rules.toOwnedSlice(allocator);
                }
            }
            linux_spec.seccomp = seccomp_spec;
        }
        // Parse resources
        if (lnx.object.get("resources")) |res| {
            var linux_res = LinuxResources{};
            if (res.object.get("memory")) |mem| {
                var mr = MemoryResources{};
                if (mem.object.get("limit")) |l| {
                    if (l == .integer) mr.limit = l.integer;
                }
                if (mem.object.get("swap")) |s| {
                    if (s == .integer) mr.swap = s.integer;
                }
                linux_res.memory = mr;
            }
            if (res.object.get("cpu")) |cpu| {
                var cr = CpuResources{};
                if (cpu.object.get("shares")) |s| {
                    if (s == .integer) cr.shares = @intCast(s.integer);
                }
                if (cpu.object.get("quota")) |q| {
                    if (q == .integer) cr.quota = q.integer;
                }
                if (cpu.object.get("period")) |p| {
                    if (p == .integer) cr.period = @intCast(p.integer);
                }
                if (cpu.object.get("cpus")) |c| {
                    if (c == .string) cr.cpus = try allocator.dupe(u8, c.string);
                }
                linux_res.cpu = cr;
            }
            if (res.object.get("pids")) |pids| {
                if (pids.object.get("limit")) |l| {
                    if (l == .integer) linux_res.pids = .{ .limit = l.integer };
                }
            }
            linux_spec.resources = linux_res;
        }
        spec.linux = linux_spec;
    }

    return spec;
}

fn parseStringArray(allocator: std.mem.Allocator, value: std.json.Value) ![]const []const u8 {
    if (value != .array) return &.{};
    var list: std.ArrayListUnmanaged([]const u8) = .{};
    for (value.array.items) |item| {
        if (item == .string) {
            try list.append(allocator, try allocator.dupe(u8, item.string));
        }
    }
    return try list.toOwnedSlice(allocator);
}

/// Convert OCI runtime spec resources to cgroup Resources
pub fn toCgroupResources(linux_res: *const LinuxResources) @import("linux/cgroup.zig").Resources {
    var res = @import("linux/cgroup.zig").Resources{};

    if (linux_res.memory) |mem| {
        if (mem.limit) |limit| {
            if (limit > 0) res.memory_max = @intCast(limit);
        }
        if (mem.swap) |swap| {
            if (swap > 0) res.memory_swap_max = @intCast(swap);
        }
    }

    if (linux_res.cpu) |cpu| {
        if (cpu.quota) |quota| {
            if (quota > 0) res.cpu_quota = @intCast(quota);
        }
        if (cpu.period) |period| {
            res.cpu_period = period;
        }
        if (cpu.shares) |shares| {
            // OCI uses shares (2-262144), cgroup v2 uses weight (1-10000)
            // Approximate conversion: weight = 1 + (shares - 2) * 9999 / 262142
            if (shares > 2) {
                res.cpu_weight = @intCast(@min(10000, 1 + (shares - 2) * 9999 / 262142));
            }
        }
        res.cpuset = cpu.cpus;
    }

    if (linux_res.pids) |pids| {
        if (pids.limit > 0) res.pids_max = @intCast(pids.limit);
    }

    return res;
}

test "default spec" {
    const spec = Spec{};
    try std.testing.expectEqualStrings("1.0.2", spec.ociVersion);
    try std.testing.expect(spec.root == null);
    try std.testing.expect(spec.process == null);
}

test "default process" {
    const proc = Process{};
    try std.testing.expect(!proc.terminal);
    try std.testing.expectEqualStrings("/", proc.cwd);
    try std.testing.expect(proc.noNewPrivileges);
}

test "parse minimal config.json" {
    const json =
        \\{"ociVersion":"1.0.2","root":{"path":"rootfs"},"process":{"args":["/bin/sh"],"cwd":"/home","env":["PATH=/usr/bin","HOME=/root"]}}
    ;
    const spec = try parseConfigManual(std.testing.allocator, json);
    try std.testing.expectEqualStrings("1.0.2", spec.ociVersion);
    try std.testing.expect(spec.root != null);
    try std.testing.expectEqualStrings("rootfs", spec.root.?.path);
    try std.testing.expect(spec.process != null);
    try std.testing.expectEqualStrings("/home", spec.process.?.cwd);
    try std.testing.expect(spec.process.?.args != null);
    try std.testing.expectEqual(@as(usize, 1), spec.process.?.args.?.len);
    try std.testing.expectEqualStrings("/bin/sh", spec.process.?.args.?[0]);
    try std.testing.expect(spec.process.?.env != null);
    try std.testing.expectEqual(@as(usize, 2), spec.process.?.env.?.len);

    // Cleanup
    std.testing.allocator.free(spec.ociVersion);
    std.testing.allocator.free(spec.root.?.path);
    std.testing.allocator.free(spec.process.?.cwd);
    for (spec.process.?.args.?) |a| std.testing.allocator.free(a);
    std.testing.allocator.free(spec.process.?.args.?);
    for (spec.process.?.env.?) |e| std.testing.allocator.free(e);
    std.testing.allocator.free(spec.process.?.env.?);
}

test "toCgroupResources memory" {
    const res = LinuxResources{
        .memory = .{ .limit = 512 * 1024 * 1024, .swap = 1024 * 1024 * 1024 },
    };
    const cg = toCgroupResources(&res);
    try std.testing.expectEqual(@as(u64, 512 * 1024 * 1024), cg.memory_max);
    try std.testing.expectEqual(@as(u64, 1024 * 1024 * 1024), cg.memory_swap_max);
}

test "toCgroupResources cpu" {
    const res = LinuxResources{
        .cpu = .{ .quota = 50000, .period = 100000, .shares = 1024 },
    };
    const cg = toCgroupResources(&res);
    try std.testing.expectEqual(@as(u64, 50000), cg.cpu_quota);
    try std.testing.expectEqual(@as(u64, 100000), cg.cpu_period);
    try std.testing.expect(cg.cpu_weight > 0);
}

test "toCgroupResources pids" {
    const res = LinuxResources{
        .pids = .{ .limit = 100 },
    };
    const cg = toCgroupResources(&res);
    try std.testing.expectEqual(@as(u32, 100), cg.pids_max);
}
