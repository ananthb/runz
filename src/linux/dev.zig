const std = @import("std");
const syscall = @import("syscall.zig");
const log = @import("../log.zig");

const scoped_log = log.scoped("dev");

const DeviceNode = struct {
    name: []const u8,
    host_path: []const u8,
};

const minimal_devices = [_]DeviceNode{
    .{ .name = "null", .host_path = "/dev/null" },
    .{ .name = "zero", .host_path = "/dev/zero" },
    .{ .name = "random", .host_path = "/dev/random" },
    .{ .name = "urandom", .host_path = "/dev/urandom" },
    .{ .name = "tty", .host_path = "/dev/tty" },
};

/// Set up minimal /dev in the rootfs using a tmpfs + bind mounts from host
pub fn setupMinimalDev(allocator: std.mem.Allocator, rootfs_path: []const u8) !void {
    const dev_path = try std.fmt.allocPrint(allocator, "{s}/dev", .{rootfs_path});
    defer allocator.free(dev_path);

    // Create /dev directory and subdirs
    {
        var dir = try std.fs.openDirAbsolute(rootfs_path, .{});
        defer dir.close();
        dir.makePath("dev") catch {};
        dir.makePath("dev/pts") catch {};
        dir.makePath("dev/shm") catch {};
    }

    // Mount tmpfs on /dev
    var dev_z_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (dev_path.len >= dev_z_buf.len) return error.OutOfMemory;
    @memcpy(dev_z_buf[0..dev_path.len], dev_path);
    dev_z_buf[dev_path.len] = 0;
    const dev_z: [*:0]const u8 = @ptrCast(dev_z_buf[0..dev_path.len :0]);

    syscall.mount("tmpfs", dev_z, "tmpfs", .{ .nosuid = true, .noexec = true }, @ptrCast("size=65536k,mode=755")) catch |err| {
        scoped_log.warn("Failed to mount tmpfs on /dev: {}, will try bind mounts anyway", .{err});
    };

    // Bind mount each device from host
    for (minimal_devices) |device| {
        const target = std.fmt.allocPrint(allocator, "{s}/dev/{s}", .{ rootfs_path, device.name }) catch continue;
        defer allocator.free(target);

        // Create target file
        {
            var dev_dir = std.fs.openDirAbsolute(dev_path, .{}) catch continue;
            defer dev_dir.close();
            var f = dev_dir.createFile(device.name, .{}) catch continue;
            f.close();
        }

        var target_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (target.len >= target_buf.len) continue;
        @memcpy(target_buf[0..target.len], target);
        target_buf[target.len] = 0;
        const target_z: [*:0]const u8 = @ptrCast(target_buf[0..target.len :0]);

        var host_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (device.host_path.len >= host_buf.len) continue;
        @memcpy(host_buf[0..device.host_path.len], device.host_path);
        host_buf[device.host_path.len] = 0;
        const host_z: [*:0]const u8 = @ptrCast(host_buf[0..device.host_path.len :0]);

        syscall.mount(host_z, target_z, null, .{ .bind = true }, null) catch |err| {
            scoped_log.warn("Failed to bind mount {s}: {}", .{ device.name, err });
        };
    }

    // Create symlinks
    {
        var dev_dir = std.fs.openDirAbsolute(dev_path, .{}) catch return;
        defer dev_dir.close();
        dev_dir.symLink("/proc/self/fd/0", "stdin", .{}) catch {};
        dev_dir.symLink("/proc/self/fd/1", "stdout", .{}) catch {};
        dev_dir.symLink("/proc/self/fd/2", "stderr", .{}) catch {};
        dev_dir.symLink("/proc/self/fd", "fd", .{}) catch {};
    }
}

test "device node list" {
    // Verify the minimal device list is correct
    try std.testing.expectEqual(minimal_devices.len, 5);
    try std.testing.expectEqualStrings("null", minimal_devices[0].name);
    try std.testing.expectEqualStrings("/dev/null", minimal_devices[0].host_path);
}
