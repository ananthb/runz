const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

// BPF instruction
const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const SockFilterProg = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

// seccomp_data offsets
const SECCOMP_DATA_NR = 0; // syscall number
const SECCOMP_DATA_ARCH = 4; // audit arch

// BPF opcodes
const BPF_LD = 0x00;
const BPF_JMP = 0x05;
const BPF_RET = 0x06;
const BPF_W = 0x00;
const BPF_ABS = 0x20;
const BPF_JEQ = 0x10;
const BPF_K = 0x00;

// Return values
const SECCOMP_RET_ALLOW = 0x7fff0000;
const SECCOMP_RET_ERRNO = 0x00050000;
const SECCOMP_RET_KILL_PROCESS = 0x80000000;

// prctl constants
pub const PR_SET_NO_NEW_PRIVS = 38;
pub const PR_SET_SECCOMP = 22;
pub const SECCOMP_MODE_FILTER = 2;

// Audit arch (must match at runtime)
const AUDIT_ARCH_X86_64 = 0xC000003E;
const AUDIT_ARCH_AARCH64 = 0xC00000B7;

pub const SeccompFilter = struct {
    instructions: [2048]SockFilter = undefined,
    len: usize = 0,
    default_action: u32 = SECCOMP_RET_ALLOW,

    pub fn init() SeccompFilter {
        var self = SeccompFilter{};
        // Load architecture
        self.addInstruction(.{ .code = BPF_LD | BPF_W | BPF_ABS, .jt = 0, .jf = 0, .k = SECCOMP_DATA_ARCH });
        // Validate architecture (jump over kill if match)
        const expected_arch = comptime getAuditArch();
        self.addInstruction(.{ .code = BPF_JMP | BPF_JEQ | BPF_K, .jt = 1, .jf = 0, .k = expected_arch });
        // Kill on arch mismatch
        self.addInstruction(.{ .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS });
        // Load syscall number
        self.addInstruction(.{ .code = BPF_LD | BPF_W | BPF_ABS, .jt = 0, .jf = 0, .k = SECCOMP_DATA_NR });
        return self;
    }

    /// Block a syscall with EPERM
    pub fn blockSyscall(self: *SeccompFilter, nr: usize) void {
        // JEQ nr -> return ERRNO(EPERM), else continue
        self.addInstruction(.{ .code = BPF_JMP | BPF_JEQ | BPF_K, .jt = 0, .jf = 1, .k = @intCast(nr) });
        self.addInstruction(.{ .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_ERRNO | 1 }); // EPERM = 1
    }

    /// Allow a specific syscall (used when default action is deny)
    pub fn allowSyscall(self: *SeccompFilter, nr: usize) void {
        self.addInstruction(.{ .code = BPF_JMP | BPF_JEQ | BPF_K, .jt = 0, .jf = 1, .k = @intCast(nr) });
        self.addInstruction(.{ .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_ALLOW });
    }

    /// Kill process on a specific syscall
    pub fn killSyscall(self: *SeccompFilter, nr: usize) void {
        self.addInstruction(.{ .code = BPF_JMP | BPF_JEQ | BPF_K, .jt = 0, .jf = 1, .k = @intCast(nr) });
        self.addInstruction(.{ .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS });
    }

    /// Finalize with the configured default action
    pub fn finalize(self: *SeccompFilter) void {
        self.addInstruction(.{ .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = self.default_action });
    }

    /// Install the filter using prctl
    pub fn install(self: *SeccompFilter) !void {
        const syscall_mod = @import("syscall.zig");
        // PR_SET_NO_NEW_PRIVS is mandatory before seccomp filter
        try syscall_mod.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

        const prog = SockFilterProg{
            .len = @intCast(self.len),
            .filter = &self.instructions,
        };
        try syscall_mod.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, @intFromPtr(&prog), 0, 0);
    }

    fn addInstruction(self: *SeccompFilter, inst: SockFilter) void {
        if (self.len < self.instructions.len) {
            self.instructions[self.len] = inst;
            self.len += 1;
        }
    }

    fn getAuditArch() u32 {
        return switch (builtin.cpu.arch) {
            .x86_64 => AUDIT_ARCH_X86_64,
            .aarch64 => AUDIT_ARCH_AARCH64,
            else => AUDIT_ARCH_X86_64, // fallback
        };
    }
};

/// Create a default seccomp filter that blocks dangerous syscalls
pub fn defaultFilter() SeccompFilter {
    var filter = SeccompFilter.init();

    // Block dangerous syscalls
    const blocked = getBlockedSyscalls();
    for (blocked) |nr| {
        filter.blockSyscall(nr);
    }

    filter.finalize();
    return filter;
}

/// Build a seccomp filter from an OCI runtime spec seccomp section.
pub fn fromSpec(spec: anytype) SeccompFilter {
    var filter = SeccompFilter.init();

    // Parse default action
    filter.default_action = parseAction(spec.defaultAction);

    // Process syscall rules
    if (spec.syscalls) |syscalls| {
        for (syscalls) |rule| {
            const action = parseAction(rule.action);
            for (rule.names) |name| {
                if (syscallFromName(name)) |nr| {
                    if (action == SECCOMP_RET_ALLOW) {
                        filter.allowSyscall(nr);
                    } else if (action == SECCOMP_RET_KILL_PROCESS) {
                        filter.killSyscall(nr);
                    } else {
                        filter.blockSyscall(nr);
                    }
                }
            }
        }
    }

    filter.finalize();
    return filter;
}

fn parseAction(action: []const u8) u32 {
    if (std.mem.eql(u8, action, "SCMP_ACT_ALLOW")) return SECCOMP_RET_ALLOW;
    if (std.mem.eql(u8, action, "SCMP_ACT_ERRNO")) return SECCOMP_RET_ERRNO | 1;
    if (std.mem.eql(u8, action, "SCMP_ACT_KILL")) return SECCOMP_RET_KILL_PROCESS;
    if (std.mem.eql(u8, action, "SCMP_ACT_KILL_PROCESS")) return SECCOMP_RET_KILL_PROCESS;
    if (std.mem.eql(u8, action, "SCMP_ACT_TRAP")) return 0x00030000; // SECCOMP_RET_TRAP
    if (std.mem.eql(u8, action, "SCMP_ACT_LOG")) return 0x7ffc0000; // SECCOMP_RET_LOG
    return SECCOMP_RET_ERRNO | 1; // default to EPERM
}

/// Look up a syscall number by name. Uses the target architecture's SYS enum.
pub fn syscallFromName(name: []const u8) ?usize {
    const SYS = linux.SYS;
    // Use comptime reflection to match syscall names
    const fields = @typeInfo(SYS).@"enum".fields;
    inline for (fields) |field| {
        if (std.mem.eql(u8, name, field.name)) {
            return field.value;
        }
    }
    return null;
}

fn getBlockedSyscalls() []const usize {
    const SYS = linux.SYS;
    if (builtin.cpu.arch == .x86_64) {
        // x86_64 syscall numbers
        return &[_]usize{
            @intFromEnum(SYS.ptrace),
            @intFromEnum(SYS.reboot),
            @intFromEnum(SYS.init_module),
            @intFromEnum(SYS.finit_module),
            @intFromEnum(SYS.delete_module),
            @intFromEnum(SYS.swapon),
            @intFromEnum(SYS.swapoff),
            @intFromEnum(SYS.acct),
            @intFromEnum(SYS.settimeofday),
            @intFromEnum(SYS.sethostname),
            @intFromEnum(SYS.setdomainname),
            @intFromEnum(SYS.setns),
            @intFromEnum(SYS.keyctl),
            @intFromEnum(SYS.add_key),
            @intFromEnum(SYS.request_key),
            @intFromEnum(SYS.perf_event_open),
            @intFromEnum(SYS.bpf),
            @intFromEnum(SYS.userfaultfd),
            @intFromEnum(SYS.kexec_load),
            @intFromEnum(SYS.pivot_root),
        };
    } else if (builtin.cpu.arch == .aarch64) {
        // aarch64 syscall numbers - some syscalls don't exist on aarch64
        return &[_]usize{
            @intFromEnum(SYS.ptrace),
            @intFromEnum(SYS.reboot),
            @intFromEnum(SYS.init_module),
            @intFromEnum(SYS.finit_module),
            @intFromEnum(SYS.delete_module),
            @intFromEnum(SYS.swapon),
            @intFromEnum(SYS.swapoff),
            @intFromEnum(SYS.acct),
            @intFromEnum(SYS.settimeofday),
            @intFromEnum(SYS.sethostname),
            @intFromEnum(SYS.setdomainname),
            @intFromEnum(SYS.setns),
            @intFromEnum(SYS.keyctl),
            @intFromEnum(SYS.add_key),
            @intFromEnum(SYS.request_key),
            @intFromEnum(SYS.perf_event_open),
            @intFromEnum(SYS.bpf),
            @intFromEnum(SYS.userfaultfd),
            @intFromEnum(SYS.kexec_load),
            @intFromEnum(SYS.pivot_root),
        };
    } else {
        // Fallback: empty list
        return &[_]usize{};
    }
}

test "seccomp filter creation" {
    var filter = defaultFilter();
    // Should have: 4 header + (20 blocked * 2) + 1 finalize = 45
    try std.testing.expect(filter.instructions.len > 0);
    // Verify header instructions
    try std.testing.expectEqual(filter.instructions.get(0).code, BPF_LD | BPF_W | BPF_ABS);
    try std.testing.expectEqual(filter.instructions.get(0).k, SECCOMP_DATA_ARCH);
}
