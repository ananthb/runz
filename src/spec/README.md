# OCI Specification Types

Zig type definitions for the [Open Container Initiative](https://opencontainers.org/) specifications.

## Attribution

This code is derived from [oci-spec-zig](https://github.com/navidys/oci-spec-zig) v0.3.0
by [Navid Yaghoobi](https://github.com/navidys), licensed under the MIT License.

Patches applied for Zig 0.15 compatibility:
- `utils.zig`: `std.json.stringifyAlloc` → `std.json.Stringify.valueAlloc`
- `runtime/define.zig`: `std.ArrayList(T).init(alloc)` → `std.ArrayListUnmanaged(T)` with explicit allocator
