const std = @import("std");
const linux = std.os.linux;

/// Netlink message header (16 bytes)
pub const NlMsgHdr = extern struct {
    len: u32,
    type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
};

/// Interface info message (follows NlMsgHdr for RTM_*LINK)
pub const IfInfoMsg = extern struct {
    family: u8 = 0,
    _pad: u8 = 0,
    type: u16 = 0,
    index: i32 = 0,
    flags: u32 = 0,
    change: u32 = 0,
};

/// Interface address message (follows NlMsgHdr for RTM_*ADDR)
pub const IfAddrMsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8 = 0,
    scope: u8 = 0,
    index: u32,
};

/// Route message (follows NlMsgHdr for RTM_*ROUTE)
pub const RtMsg = extern struct {
    family: u8,
    dst_len: u8 = 0,
    src_len: u8 = 0,
    tos: u8 = 0,
    table: u8 = RT_TABLE_MAIN,
    protocol: u8 = RTPROT_BOOT,
    scope: u8 = RT_SCOPE_UNIVERSE,
    type: u8 = RTN_UNICAST,
    flags: u32 = 0,
};

/// Netlink attribute header (4 bytes, followed by payload padded to 4 bytes)
pub const NlAttr = extern struct {
    len: u16,
    type: u16,
};

// Netlink constants
pub const NETLINK_ROUTE = 0;
pub const NLM_F_REQUEST: u16 = 1;
pub const NLM_F_ACK: u16 = 4;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

// RTM message types
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_NEWROUTE: u16 = 24;

// IFLA attributes
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_NET_NS_PID: u16 = 25;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_INFO_KIND: u16 = 1;
pub const IFLA_INFO_DATA: u16 = 2;
pub const VETH_INFO_PEER: u16 = 1;

// IFA attributes
pub const IFA_LOCAL: u16 = 2;
pub const IFA_ADDRESS: u16 = 1;

// RTA attributes
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_OIF: u16 = 4;

// Interface flags
pub const IFF_UP: u32 = 1;

// Route constants
pub const RT_TABLE_MAIN: u8 = 254;
pub const RTPROT_BOOT: u8 = 3;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RTN_UNICAST: u8 = 1;

/// Align to 4 bytes (netlink attribute alignment)
pub fn nlAlign(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

/// Open a NETLINK_ROUTE socket
pub fn openSocket() !i32 {
    const fd = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, NETLINK_ROUTE);
    if (linux.E.init(fd) != .SUCCESS) return error.SocketFailed;

    // Bind to kernel
    var addr = std.mem.zeroes(linux.sockaddr.nl);
    addr.family = linux.AF.NETLINK;
    addr.pid = 0;
    addr.groups = 0;

    const bind_rc = linux.bind(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.nl));
    if (linux.E.init(bind_rc) != .SUCCESS) {
        _ = linux.close(@intCast(fd));
        return error.BindFailed;
    }

    return @intCast(fd);
}

pub fn closeSocket(fd: i32) void {
    _ = linux.close(@intCast(@as(u32, @bitCast(fd))));
}

/// Send a netlink message and wait for ACK
pub fn sendAndAck(fd: i32, buf: []const u8) !void {
    const rc = linux.sendto(
        @intCast(@as(u32, @bitCast(fd))),
        buf.ptr,
        buf.len,
        0,
        null,
        0,
    );
    if (linux.E.init(rc) != .SUCCESS) return error.SendFailed;

    // Read ACK
    var recv_buf: [4096]u8 = undefined;
    const n = linux.recvfrom(
        @intCast(@as(u32, @bitCast(fd))),
        &recv_buf,
        recv_buf.len,
        0,
        null,
        null,
    );
    if (linux.E.init(n) != .SUCCESS) return error.RecvFailed;

    // Check for NLMSG_ERROR
    if (n >= @sizeOf(NlMsgHdr)) {
        const hdr: *const NlMsgHdr = @ptrCast(@alignCast(&recv_buf));
        if (hdr.type == NLMSG_ERROR) {
            // Error code follows the header (as i32)
            if (n >= @sizeOf(NlMsgHdr) + 4) {
                const err_code: *const i32 = @ptrCast(@alignCast(recv_buf[@sizeOf(NlMsgHdr)..].ptr));
                if (err_code.* != 0) return error.NetlinkError;
            }
        }
    }
}

/// Append a netlink attribute to a buffer at offset
pub fn addAttr(buf: []u8, offset: *usize, attr_type: u16, data: []const u8) void {
    const attr_len: u16 = @intCast(@sizeOf(NlAttr) + data.len);
    const aligned_len = nlAlign(@intCast(attr_len));

    const attr: *NlAttr = @ptrCast(@alignCast(buf[offset.*..].ptr));
    attr.len = attr_len;
    attr.type = attr_type;

    if (data.len > 0) {
        @memcpy(buf[offset.* + @sizeOf(NlAttr) ..][0..data.len], data);
    }

    // Zero padding
    const pad_start = offset.* + @sizeOf(NlAttr) + data.len;
    const pad_end = offset.* + aligned_len;
    if (pad_end > pad_start) {
        @memset(buf[pad_start..pad_end], 0);
    }

    offset.* += aligned_len;
}

/// Start a nested attribute, returns the offset of the NlAttr to patch later
pub fn startNested(buf: []u8, offset: *usize, attr_type: u16) usize {
    const start = offset.*;
    const attr: *NlAttr = @ptrCast(@alignCast(buf[offset.*..].ptr));
    attr.len = 0; // patched by endNested
    attr.type = attr_type;
    offset.* += @sizeOf(NlAttr);
    return start;
}

/// End a nested attribute, patching the length
pub fn endNested(buf: []u8, start: usize, offset: usize) void {
    const attr: *NlAttr = @ptrCast(@alignCast(buf[start..].ptr));
    attr.len = @intCast(offset - start);
}

/// Add a u32 attribute
pub fn addAttrU32(buf: []u8, offset: *usize, attr_type: u16, value: u32) void {
    addAttr(buf, offset, attr_type, std.mem.asBytes(&value));
}

/// Add a string attribute (null-terminated)
pub fn addAttrStr(buf: []u8, offset: *usize, attr_type: u16, str: []const u8) void {
    // Include null terminator
    const attr_len: u16 = @intCast(@sizeOf(NlAttr) + str.len + 1);
    const aligned_len = nlAlign(@intCast(attr_len));

    const attr: *NlAttr = @ptrCast(@alignCast(buf[offset.*..].ptr));
    attr.len = attr_len;
    attr.type = attr_type;

    @memcpy(buf[offset.* + @sizeOf(NlAttr) ..][0..str.len], str);
    buf[offset.* + @sizeOf(NlAttr) + str.len] = 0;

    // Zero padding
    const pad_start = offset.* + @sizeOf(NlAttr) + str.len + 1;
    const pad_end = offset.* + aligned_len;
    if (pad_end > pad_start) {
        @memset(buf[pad_start..pad_end], 0);
    }

    offset.* += aligned_len;
}

/// Convert 4 octets to a u32 in network byte order
pub fn ipv4(a: u8, b: u8, c: u8, d: u8) u32 {
    return @as(u32, a) | (@as(u32, b) << 8) | (@as(u32, c) << 16) | (@as(u32, d) << 24);
}

/// Get interface index by name using ioctl
pub fn getIfIndex(ifname: []const u8) !i32 {
    const fd = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.E.init(fd) != .SUCCESS) return error.SocketFailed;
    defer _ = linux.close(@intCast(fd));

    // ifreq struct: 16 bytes name + 16 bytes data (we want ifr_ifindex at offset 16)
    var ifreq: [32]u8 = std.mem.zeroes([32]u8);
    const copy_len = @min(ifname.len, 15);
    @memcpy(ifreq[0..copy_len], ifname[0..copy_len]);

    const SIOCGIFINDEX = 0x8933;
    const rc = linux.syscall3(.ioctl, @intCast(fd), SIOCGIFINDEX, @intFromPtr(&ifreq));
    if (linux.E.init(rc) != .SUCCESS) return error.InterfaceNotFound;

    const index: *align(1) const i32 = @ptrCast(ifreq[16..20]);
    return index.*;
}
