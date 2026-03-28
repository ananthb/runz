const std = @import("std");
const linux = std.os.linux;
const nl = @import("netlink.zig");
const log = @import("../log.zig");

const scoped_log = log.scoped("veth");

pub const VethError = error{
    SocketFailed,
    BindFailed,
    SendFailed,
    RecvFailed,
    NetlinkError,
    InterfaceNotFound,
    SetupFailed,
};

/// Create a veth pair with the given names
pub fn createVethPair(host_name: []const u8, guest_name: []const u8) VethError!void {
    const fd = try nl.openSocket();
    defer nl.closeSocket(fd);

    var buf: [1024]u8 = std.mem.zeroes([1024]u8);
    var offset: usize = 0;

    // NlMsgHdr
    offset += @sizeOf(nl.NlMsgHdr); // filled in at the end

    // IfInfoMsg (zeroed)
    offset += @sizeOf(nl.IfInfoMsg);

    // IFLA_IFNAME = host_name
    nl.addAttrStr(&buf, &offset, nl.IFLA_IFNAME, host_name);

    // IFLA_LINKINFO (nested)
    const linkinfo_start = nl.startNested(&buf, &offset, nl.IFLA_LINKINFO);

    // IFLA_INFO_KIND = "veth"
    nl.addAttrStr(&buf, &offset, nl.IFLA_INFO_KIND, "veth");

    // IFLA_INFO_DATA (nested)
    const infodata_start = nl.startNested(&buf, &offset, nl.IFLA_INFO_DATA);

    // VETH_INFO_PEER (nested, contains IfInfoMsg + IFLA_IFNAME)
    const peer_start = nl.startNested(&buf, &offset, nl.VETH_INFO_PEER);

    // Peer IfInfoMsg (zeroed)
    offset += @sizeOf(nl.IfInfoMsg);

    // Peer IFLA_IFNAME = guest_name
    nl.addAttrStr(&buf, &offset, nl.IFLA_IFNAME, guest_name);

    nl.endNested(&buf, peer_start, offset);
    nl.endNested(&buf, infodata_start, offset);
    nl.endNested(&buf, linkinfo_start, offset);

    // Fill in header
    const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(&buf));
    hdr.len = @intCast(offset);
    hdr.type = nl.RTM_NEWLINK;
    hdr.flags = nl.NLM_F_REQUEST | nl.NLM_F_ACK | nl.NLM_F_CREATE | nl.NLM_F_EXCL;
    hdr.seq = 1;
    hdr.pid = 0;

    try nl.sendAndAck(fd, buf[0..offset]);
    scoped_log.debug("Created veth pair {s} <-> {s}", .{ host_name, guest_name });
}

/// Move an interface to another network namespace by PID
pub fn moveToNamespace(ifname: []const u8, pid: i32) VethError!void {
    const fd = try nl.openSocket();
    defer nl.closeSocket(fd);

    const ifindex = try nl.getIfIndex(ifname);

    var buf: [256]u8 = std.mem.zeroes([256]u8);
    var offset: usize = 0;

    offset += @sizeOf(nl.NlMsgHdr);

    // IfInfoMsg with the interface index
    const ifinfo: *nl.IfInfoMsg = @ptrCast(@alignCast(buf[offset..].ptr));
    ifinfo.* = .{ .index = ifindex };
    offset += @sizeOf(nl.IfInfoMsg);

    // IFLA_NET_NS_PID
    nl.addAttrU32(&buf, &offset, nl.IFLA_NET_NS_PID, @bitCast(pid));

    const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(&buf));
    hdr.len = @intCast(offset);
    hdr.type = nl.RTM_NEWLINK;
    hdr.flags = nl.NLM_F_REQUEST | nl.NLM_F_ACK;
    hdr.seq = 2;

    try nl.sendAndAck(fd, buf[0..offset]);
    scoped_log.debug("Moved {s} to namespace of pid {d}", .{ ifname, pid });
}

/// Set an interface UP
pub fn setUp(ifname: []const u8) VethError!void {
    const fd = try nl.openSocket();
    defer nl.closeSocket(fd);

    const ifindex = try nl.getIfIndex(ifname);

    var buf: [256]u8 = std.mem.zeroes([256]u8);
    var offset: usize = 0;

    offset += @sizeOf(nl.NlMsgHdr);

    const ifinfo: *nl.IfInfoMsg = @ptrCast(@alignCast(buf[offset..].ptr));
    ifinfo.* = .{ .index = ifindex, .flags = nl.IFF_UP, .change = nl.IFF_UP };
    offset += @sizeOf(nl.IfInfoMsg);

    const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(&buf));
    hdr.len = @intCast(offset);
    hdr.type = nl.RTM_NEWLINK;
    hdr.flags = nl.NLM_F_REQUEST | nl.NLM_F_ACK;
    hdr.seq = 3;

    try nl.sendAndAck(fd, buf[0..offset]);
}

/// Add an IPv4 address to an interface
pub fn addAddress(ifname: []const u8, addr: u32, prefix_len: u8) VethError!void {
    const fd = try nl.openSocket();
    defer nl.closeSocket(fd);

    const ifindex = try nl.getIfIndex(ifname);

    var buf: [256]u8 = std.mem.zeroes([256]u8);
    var offset: usize = 0;

    offset += @sizeOf(nl.NlMsgHdr);

    const ifa: *nl.IfAddrMsg = @ptrCast(@alignCast(buf[offset..].ptr));
    ifa.* = .{
        .family = linux.AF.INET,
        .prefixlen = prefix_len,
        .index = @intCast(ifindex),
    };
    offset += @sizeOf(nl.IfAddrMsg);

    nl.addAttr(&buf, &offset, nl.IFA_LOCAL, std.mem.asBytes(&addr));
    nl.addAttr(&buf, &offset, nl.IFA_ADDRESS, std.mem.asBytes(&addr));

    const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(&buf));
    hdr.len = @intCast(offset);
    hdr.type = nl.RTM_NEWADDR;
    hdr.flags = nl.NLM_F_REQUEST | nl.NLM_F_ACK | nl.NLM_F_CREATE | nl.NLM_F_EXCL;
    hdr.seq = 4;

    try nl.sendAndAck(fd, buf[0..offset]);
}

/// Add a default route via a gateway
pub fn addDefaultRoute(gateway: u32, oif_name: []const u8) VethError!void {
    const fd = try nl.openSocket();
    defer nl.closeSocket(fd);

    const oif_index = try nl.getIfIndex(oif_name);

    var buf: [256]u8 = std.mem.zeroes([256]u8);
    var offset: usize = 0;

    offset += @sizeOf(nl.NlMsgHdr);

    const rtm: *nl.RtMsg = @ptrCast(@alignCast(buf[offset..].ptr));
    rtm.* = .{ .family = linux.AF.INET };
    offset += @sizeOf(nl.RtMsg);

    nl.addAttr(&buf, &offset, nl.RTA_GATEWAY, std.mem.asBytes(&gateway));
    nl.addAttrU32(&buf, &offset, nl.RTA_OIF, @bitCast(oif_index));

    const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(&buf));
    hdr.len = @intCast(offset);
    hdr.type = nl.RTM_NEWROUTE;
    hdr.flags = nl.NLM_F_REQUEST | nl.NLM_F_ACK | nl.NLM_F_CREATE;
    hdr.seq = 5;

    try nl.sendAndAck(fd, buf[0..offset]);
}

/// Delete an interface by name
pub fn deleteInterface(ifname: []const u8) void {
    const fd = nl.openSocket() catch return;
    defer nl.closeSocket(fd);

    const ifindex = nl.getIfIndex(ifname) catch return;

    var buf: [256]u8 = std.mem.zeroes([256]u8);
    var offset: usize = 0;

    offset += @sizeOf(nl.NlMsgHdr);

    const ifinfo: *nl.IfInfoMsg = @ptrCast(@alignCast(buf[offset..].ptr));
    ifinfo.* = .{ .index = ifindex };
    offset += @sizeOf(nl.IfInfoMsg);

    const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(&buf));
    hdr.len = @intCast(offset);
    hdr.type = nl.RTM_DELLINK;
    hdr.flags = nl.NLM_F_REQUEST | nl.NLM_F_ACK;
    hdr.seq = 6;

    nl.sendAndAck(fd, buf[0..offset]) catch {};
}

/// Bring up loopback interface
pub fn setLoopbackUp() VethError!void {
    return setUp("lo");
}

/// Enable IPv4 forwarding via procfs
pub fn enableIpForwarding() !void {
    const file = std.fs.openFileAbsolute("/proc/sys/net/ipv4/ip_forward", .{ .mode = .write_only }) catch return error.SetupFailed;
    defer file.close();
    file.writeAll("1") catch return error.SetupFailed;
}

/// Set up masquerade NAT using nftables netlink.
/// Creates table "oci_nat" with a postrouting masquerade chain.
pub fn setupMasquerade() !void {
    const NETLINK_NETFILTER = 12;
    const fd_raw = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, NETLINK_NETFILTER);
    if (linux.E.init(fd_raw) != .SUCCESS) return error.SetupFailed;
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(@intCast(@as(u32, @bitCast(fd))));

    var addr = std.mem.zeroes(linux.sockaddr.nl);
    addr.family = linux.AF.NETLINK;
    const bind_rc = linux.bind(@intCast(@as(u32, @bitCast(fd))), @ptrCast(&addr), @sizeOf(linux.sockaddr.nl));
    if (linux.E.init(bind_rc) != .SUCCESS) return error.SetupFailed;

    // Build nftables batch: table + chain + masquerade rule
    var buf: [2048]u8 = std.mem.zeroes([2048]u8);
    var offset: usize = 0;

    // Constants for nftables netlink
    const NFNL_SUBSYS_NFTABLES: u16 = 10;
    const NFT_MSG_NEWTABLE: u16 = 0;
    const NFT_MSG_NEWCHAIN: u16 = 2;
    const NFT_MSG_NEWRULE: u16 = 6;
    const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
    const NFNL_MSG_BATCH_END: u16 = 0x11;
    const NFPROTO_IPV4: u8 = 2;
    const NF_INET_POST_ROUTING: u32 = 4;

    // nftables attribute types
    const NFTA_TABLE_NAME: u16 = 1;
    const NFTA_CHAIN_TABLE: u16 = 1;
    const NFTA_CHAIN_NAME: u16 = 3;
    const NFTA_CHAIN_HOOK: u16 = 4;
    const NFTA_CHAIN_TYPE: u16 = 7;
    const NFTA_HOOK_HOOKNUM: u16 = 1;
    const NFTA_HOOK_PRIORITY: u16 = 2;
    const NFTA_RULE_TABLE: u16 = 1;
    const NFTA_RULE_CHAIN: u16 = 2;
    const NFTA_RULE_EXPRESSIONS: u16 = 4;
    const NFTA_LIST_ELEM: u16 = 1;
    const NFTA_EXPR_NAME: u16 = 1;
    const NFTA_EXPR_DATA: u16 = 2;

    const table_name = "oci_nat";
    const chain_name = "postrouting";

    // --- BATCH BEGIN ---
    {
        const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(buf[offset..].ptr));
        hdr.type = NFNL_MSG_BATCH_BEGIN;
        hdr.flags = nl.NLM_F_REQUEST;
        hdr.seq = 0;
        offset += @sizeOf(nl.NlMsgHdr);
        // nfgenmsg (4 bytes)
        buf[offset] = 0; // family
        buf[offset + 1] = 0; // version
        buf[offset + 2] = 0; // res_id (u16 LE)
        buf[offset + 3] = 0;
        offset += 4;
        hdr.len = @intCast(offset);
    }

    // --- NFT_MSG_NEWTABLE ---
    const table_start = offset;
    {
        const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(buf[offset..].ptr));
        hdr.type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE;
        hdr.flags = nl.NLM_F_REQUEST | nl.NLM_F_ACK | nl.NLM_F_CREATE;
        hdr.seq = 1;
        offset += @sizeOf(nl.NlMsgHdr);
        // nfgenmsg
        buf[offset] = NFPROTO_IPV4;
        buf[offset + 1] = 0;
        buf[offset + 2] = 0;
        buf[offset + 3] = 0;
        offset += 4;
        nl.addAttrStr(&buf, &offset, NFTA_TABLE_NAME, table_name);
        hdr.len = @intCast(offset - table_start);
    }

    // --- NFT_MSG_NEWCHAIN ---
    const chain_start = offset;
    {
        const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(buf[offset..].ptr));
        hdr.type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN;
        hdr.flags = nl.NLM_F_REQUEST | nl.NLM_F_ACK | nl.NLM_F_CREATE;
        hdr.seq = 2;
        offset += @sizeOf(nl.NlMsgHdr);
        // nfgenmsg
        buf[offset] = NFPROTO_IPV4;
        buf[offset + 1] = 0;
        buf[offset + 2] = 0;
        buf[offset + 3] = 0;
        offset += 4;
        nl.addAttrStr(&buf, &offset, NFTA_CHAIN_TABLE, table_name);
        nl.addAttrStr(&buf, &offset, NFTA_CHAIN_NAME, chain_name);
        nl.addAttrStr(&buf, &offset, NFTA_CHAIN_TYPE, "nat");

        // NFTA_CHAIN_HOOK (nested: hooknum + priority)
        const hook_start = nl.startNested(&buf, &offset, NFTA_CHAIN_HOOK);
        nl.addAttrU32(&buf, &offset, NFTA_HOOK_HOOKNUM, std.mem.nativeToBig(u32, NF_INET_POST_ROUTING));
        nl.addAttrU32(&buf, &offset, NFTA_HOOK_PRIORITY, std.mem.nativeToBig(u32, 100));
        nl.endNested(&buf, hook_start, offset);

        hdr.len = @intCast(offset - chain_start);
    }

    // --- NFT_MSG_NEWRULE (masquerade) ---
    const rule_start = offset;
    {
        const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(buf[offset..].ptr));
        hdr.type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE;
        hdr.flags = nl.NLM_F_REQUEST | nl.NLM_F_ACK | nl.NLM_F_CREATE;
        hdr.seq = 3;
        offset += @sizeOf(nl.NlMsgHdr);
        // nfgenmsg
        buf[offset] = NFPROTO_IPV4;
        buf[offset + 1] = 0;
        buf[offset + 2] = 0;
        buf[offset + 3] = 0;
        offset += 4;
        nl.addAttrStr(&buf, &offset, NFTA_RULE_TABLE, table_name);
        nl.addAttrStr(&buf, &offset, NFTA_RULE_CHAIN, chain_name);

        // NFTA_RULE_EXPRESSIONS (nested list of expressions)
        const exprs_start = nl.startNested(&buf, &offset, NFTA_RULE_EXPRESSIONS);

        // Single expression: masquerade
        const elem_start = nl.startNested(&buf, &offset, NFTA_LIST_ELEM);
        nl.addAttrStr(&buf, &offset, NFTA_EXPR_NAME, "masq");
        // NFTA_EXPR_DATA - empty nested (masq has no mandatory attrs)
        const data_start = nl.startNested(&buf, &offset, NFTA_EXPR_DATA);
        nl.endNested(&buf, data_start, offset);
        nl.endNested(&buf, elem_start, offset);

        nl.endNested(&buf, exprs_start, offset);

        hdr.len = @intCast(offset - rule_start);
    }

    // --- BATCH END ---
    {
        const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(buf[offset..].ptr));
        hdr.type = NFNL_MSG_BATCH_END;
        hdr.flags = nl.NLM_F_REQUEST;
        hdr.seq = 4;
        offset += @sizeOf(nl.NlMsgHdr);
        // nfgenmsg
        buf[offset] = 0;
        buf[offset + 1] = 0;
        buf[offset + 2] = 0;
        buf[offset + 3] = 0;
        offset += 4;
        hdr.len = @intCast(@sizeOf(nl.NlMsgHdr) + 4);
    }

    // Send the whole batch
    const rc = linux.sendto(
        @intCast(@as(u32, @bitCast(fd))),
        buf[0..offset].ptr,
        offset,
        0,
        null,
        0,
    );
    if (linux.E.init(rc) != .SUCCESS) return error.SetupFailed;

    // Read responses (one ACK per message in the batch)
    var recv_buf: [4096]u8 = undefined;
    for (0..3) |_| {
        const n = linux.recvfrom(
            @intCast(@as(u32, @bitCast(fd))),
            &recv_buf,
            recv_buf.len,
            0,
            null,
            null,
        );
        if (linux.E.init(n) != .SUCCESS) break;
    }

    scoped_log.debug("Set up NAT masquerade (oci_nat table)", .{});
}

/// Remove the oci_nat nftables table
pub fn teardownMasquerade() void {
    const NETLINK_NETFILTER = 12;
    const fd_raw = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, NETLINK_NETFILTER);
    if (linux.E.init(fd_raw) != .SUCCESS) return;
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(@intCast(@as(u32, @bitCast(fd))));

    var addr = std.mem.zeroes(linux.sockaddr.nl);
    addr.family = linux.AF.NETLINK;
    _ = linux.bind(@intCast(@as(u32, @bitCast(fd))), @ptrCast(&addr), @sizeOf(linux.sockaddr.nl));

    const NFNL_SUBSYS_NFTABLES: u16 = 10;
    const NFT_MSG_DELTABLE: u16 = 1;
    const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
    const NFNL_MSG_BATCH_END: u16 = 0x11;
    const NFPROTO_IPV4: u8 = 2;
    const NFTA_TABLE_NAME: u16 = 1;

    var buf: [512]u8 = std.mem.zeroes([512]u8);
    var offset: usize = 0;

    // BATCH BEGIN
    {
        const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(buf[offset..].ptr));
        hdr.type = NFNL_MSG_BATCH_BEGIN;
        hdr.flags = nl.NLM_F_REQUEST;
        offset += @sizeOf(nl.NlMsgHdr);
        offset += 4; // nfgenmsg
        hdr.len = @intCast(@sizeOf(nl.NlMsgHdr) + 4);
    }

    // NFT_MSG_DELTABLE
    const del_start = offset;
    {
        const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(buf[offset..].ptr));
        hdr.type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE;
        hdr.flags = nl.NLM_F_REQUEST | nl.NLM_F_ACK;
        hdr.seq = 1;
        offset += @sizeOf(nl.NlMsgHdr);
        buf[offset] = NFPROTO_IPV4;
        offset += 4;
        nl.addAttrStr(&buf, &offset, NFTA_TABLE_NAME, "oci_nat");
        hdr.len = @intCast(offset - del_start);
    }

    // BATCH END
    {
        const hdr: *nl.NlMsgHdr = @ptrCast(@alignCast(buf[offset..].ptr));
        hdr.type = NFNL_MSG_BATCH_END;
        hdr.flags = nl.NLM_F_REQUEST;
        offset += @sizeOf(nl.NlMsgHdr);
        offset += 4;
        hdr.len = @intCast(@sizeOf(nl.NlMsgHdr) + 4);
    }

    _ = linux.sendto(@intCast(@as(u32, @bitCast(fd))), buf[0..offset].ptr, offset, 0, null, 0);

    scoped_log.debug("Removed NAT masquerade (oci_nat table)", .{});
}
