//! runz - OCI container runtime and library
//!
//! Container runtime with image pulling, layer extraction,
//! namespace isolation, cgroups, capabilities, networking,
//! and OCI runtime spec support.

/// OCI spec types (image, runtime, distribution)
pub const spec = @import("ocispec");

/// OCI image reference parsing and types
pub const image = @import("image.zig");

/// Registry HTTP client (pull, auth, platform resolution)
pub const registry = @import("registry.zig");

/// Registry authentication (token fetching, WWW-Authenticate parsing)
pub const auth = @import("auth.zig");

/// Layer extraction and whiteout handling
pub const layer = @import("layer.zig");

/// Blob caching
pub const cache = @import("cache.zig");

/// OCI image layout writer
pub const layout_writer = @import("layout_writer.zig");

/// Containerfile/Dockerfile parser
pub const containerfile = @import("containerfile.zig");

/// Container command execution (RUN support via chroot)
pub const run = @import("run.zig");

/// Container lifecycle management (create, start, kill, delete)
pub const container = @import("container.zig");

/// OCI Runtime Spec (config.json parsing)
pub const runtime_spec = @import("runtime_spec.zig");

/// OCI lifecycle hooks
pub const hooks = @import("hooks.zig");

/// Daemonless container runner (like podman run)
pub const runz = @import("runz.zig");

/// Run a container from an OCI runtime spec bundle
pub const spec_run = @import("spec_run.zig");

/// Execute processes inside running containers (nsenter)
pub const exec = @import("exec.zig");

/// Logging (set log level, colors)
pub const log = @import("log.zig");

/// OCI annotations support
pub const annotations = @import("annotations.zig");

/// Linux-specific utilities (namespaces, mounts, seccomp, cgroups, capabilities)
pub const linux_util = @import("linux.zig");
