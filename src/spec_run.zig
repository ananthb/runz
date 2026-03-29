const std = @import("std");
const linux = std.os.linux;
const log = @import("log.zig");
const runtime_spec = @import("runtime_spec.zig");
const run = @import("run.zig");
const cgroup = @import("linux/cgroup.zig");
const capabilities = @import("linux/capabilities.zig");
const seccomp = @import("linux/seccomp.zig");
const paths = @import("linux/paths.zig");
const security = @import("linux/security.zig");
const hooks = @import("hooks.zig");
const syscall = @import("linux/syscall.zig");

const scoped_log = log.scoped("spec-run");

pub const SpecRunError = error{
    InvalidSpec,
    MissingRootfs,
    MissingProcess,
    ContainerFailed,
    OutOfMemory,
    SetupFailed,
};

/// Run a container from an OCI runtime spec bundle.
/// This is the `runz run` implementation: reads config.json,
/// sets up the container per the spec, and blocks until exit.
pub fn runFromBundle(
    allocator: std.mem.Allocator,
    bundle_path: []const u8,
    container_id: []const u8,
    root_dir: []const u8,
) SpecRunError!u8 {
    // Read and parse config.json
    const config_path = std.fmt.allocPrint(allocator, "{s}/config.json", .{bundle_path}) catch
        return error.OutOfMemory;
    defer allocator.free(config_path);

    const spec = runtime_spec.parseConfigFile(allocator, config_path) catch |err| {
        scoped_log.err("Failed to parse config.json: {}", .{err});
        return error.InvalidSpec;
    };

    // Validate required fields
    const root = spec.root orelse {
        scoped_log.err("config.json missing 'root' field", .{});
        return error.MissingRootfs;
    };

    const process = spec.process orelse {
        scoped_log.err("config.json missing 'process' field", .{});
        return error.MissingProcess;
    };

    // Resolve rootfs path (relative to bundle)
    const rootfs_path = if (std.fs.path.isAbsolute(root.path))
        allocator.dupe(u8, root.path) catch return error.OutOfMemory
    else
        std.fmt.allocPrint(allocator, "{s}/{s}", .{ bundle_path, root.path }) catch return error.OutOfMemory;
    defer allocator.free(rootfs_path);

    scoped_log.info("Running container {s} from {s}", .{ container_id, rootfs_path });

    // Build argv from process.args
    const argv = process.args orelse {
        scoped_log.err("config.json process.args is empty", .{});
        return error.MissingProcess;
    };
    if (argv.len == 0) return error.MissingProcess;

    // Determine namespace flags from spec
    var want_netns = false;
    var want_userns = false;
    if (spec.linux) |lnx| {
        if (lnx.namespaces) |namespaces| {
            for (namespaces) |ns| {
                if (std.mem.eql(u8, ns.type, "network")) want_netns = true;
                if (std.mem.eql(u8, ns.type, "user")) want_userns = true;
            }
        }
    }

    // Determine network mode
    const network_mode: run.NetworkMode = if (want_netns) .veth else .host;

    // Build capability set from spec
    var cap_set: ?capabilities.CapSet = null;
    if (process.capabilities) |proc_caps| {
        var set = capabilities.CapSet{};
        if (proc_caps.bounding) |names| {
            set = capabilities.CapSet.fromNames(names);
        } else if (proc_caps.effective) |names| {
            set = capabilities.CapSet.fromNames(names);
        } else {
            set = capabilities.CapSet.defaultSet();
        }
        cap_set = set;
    }

    // Build container options
    var container_opts = run.ContainerOptions{
        .env = process.env,
        .network = network_mode,
        .rootless = want_userns,
        .mounts = spec.mounts,
        .capabilities = cap_set,
        .cwd = if (!std.mem.eql(u8, process.cwd, "/")) process.cwd else null,
        .seccomp = if (spec.linux) |lnx| lnx.seccomp else null,
    };

    // Set up cgroup resources if specified
    var cg_resources: ?cgroup.Resources = null;
    if (spec.linux) |lnx| {
        if (lnx.resources) |res| {
            cg_resources = runtime_spec.toCgroupResources(&res);
            container_opts.resources = &cg_resources.?;
        }
    }

    // Apply masked/readonly paths
    if (spec.linux) |lnx| {
        if (lnx.maskedPaths) |masked| {
            paths.applyMaskedPaths(rootfs_path, masked, allocator);
        } else {
            paths.applyMaskedPaths(rootfs_path, &paths.default_masked_paths, allocator);
        }
        if (lnx.readonlyPaths) |readonly| {
            paths.applyReadonlyPaths(rootfs_path, readonly, allocator);
        } else {
            paths.applyReadonlyPaths(rootfs_path, &paths.default_readonly_paths, allocator);
        }
    } else {
        paths.applyDefaults(rootfs_path, allocator);
    }

    // Build state JSON for hooks
    const state_json_for_hooks = std.fmt.allocPrint(allocator,
        \\{{"ociVersion":"1.0.2","id":"{s}","status":"creating","pid":0,"bundle":"{s}"}}
    , .{ container_id, bundle_path }) catch null;
    defer if (state_json_for_hooks) |s| allocator.free(s);

    // Execute createRuntime hooks (before container start)
    executeHooksFromConfig(allocator, config_path, "createRuntime", state_json_for_hooks);
    // Also execute legacy prestart hooks
    executeHooksFromConfig(allocator, config_path, "prestart", state_json_for_hooks);

    // Write state file
    {
        const state_json = std.fmt.allocPrint(allocator,
            \\{{"ociVersion":"1.0.2","id":"{s}","status":"running","pid":0,"bundle":"{s}"}}
        , .{ container_id, bundle_path }) catch return error.OutOfMemory;
        defer allocator.free(state_json);

        const state_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ root_dir, container_id }) catch return error.OutOfMemory;
        defer allocator.free(state_path);

        std.fs.makeDirAbsolute(root_dir) catch {};
        const dir_path = std.fs.path.dirname(state_path) orelse "/";
        var dir = std.fs.openDirAbsolute(dir_path, .{}) catch return error.SetupFailed;
        defer dir.close();
        var file = dir.createFile(std.fs.path.basename(state_path), .{}) catch return error.SetupFailed;
        defer file.close();
        file.writeAll(state_json) catch return error.SetupFailed;
    }
    // Clean up state on exit (compute path eagerly for defer)
    const cleanup_state_path = std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ root_dir, container_id }) catch null;
    defer {
        if (cleanup_state_path) |p| {
            std.fs.deleteFileAbsolute(p) catch {};
            allocator.free(p);
        }
    }

    // Run the container
    scoped_log.info("Entrypoint: {s}", .{argv[0]});
    const exit_code = run.runContainer(allocator, rootfs_path, argv, container_opts) catch |err| {
        scoped_log.err("Container failed: {}", .{err});
        return error.ContainerFailed;
    };

    // Execute poststop hooks
    {
        const stopped_state = std.fmt.allocPrint(allocator,
            \\{{"ociVersion":"1.0.2","id":"{s}","status":"stopped","pid":0,"bundle":"{s}"}}
        , .{ container_id, bundle_path }) catch null;
        defer if (stopped_state) |s| allocator.free(s);
        executeHooksFromConfig(allocator, config_path, "poststop", stopped_state);
    }

    scoped_log.info("Container {s} exited with code {d}", .{ container_id, exit_code });
    return exit_code;
}

/// Parse hooks from config.json and execute a specific hook point
fn executeHooksFromConfig(
    allocator: std.mem.Allocator,
    config_path_: []const u8,
    hook_point: []const u8,
    state_json: ?[]const u8,
) void {
    const file = std.fs.openFileAbsolute(config_path_, .{}) catch return;
    defer file.close();

    var buf: [65536]u8 = undefined;
    const n = file.readAll(&buf) catch return;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, buf[0..n], .{}) catch return;
    defer parsed.deinit();

    const hooks_val = parsed.value.object.get("hooks") orelse return;
    const hook_list_val = hooks_val.object.get(hook_point) orelse return;

    const hook_set = hooks.parseHookList(allocator, hook_list_val) catch return;
    defer {
        for (hook_set) |h| {
            allocator.free(h.path);
            if (h.args) |args| {
                for (args) |a| allocator.free(a);
                allocator.free(args);
            }
        }
        allocator.free(hook_set);
    }

    if (hook_set.len == 0) return;

    scoped_log.info("Executing {d} {s} hooks", .{ hook_set.len, hook_point });
    hooks.executeHooks(allocator, hook_set, state_json orelse "{}") catch |err| {
        scoped_log.warn("Hook {s} failed: {}", .{ hook_point, err });
    };
}
