{
  description = "OCI library for Zig - container image operations";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, pre-commit-hooks }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        version = if (self ? shortRev) then self.shortRev else "dev";

        pre-commit-check = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            # Zig formatting
            zig-fmt = {
              enable = true;
              name = "zig fmt";
              entry = "${pkgs.zig}/bin/zig fmt";
              files = "\\.zig$";
              pass_filenames = false;
              args = [ "--check" "src/" ];
            };

            # Trailing whitespace
            trailing-whitespace = {
              enable = true;
              name = "trailing whitespace";
              entry = "${pkgs.python3}/bin/python3 -c \"
import sys, pathlib
ok = True
for f in pathlib.Path('.').rglob('*.zig'):
    for i, line in enumerate(f.read_text().splitlines(), 1):
        if line != line.rstrip():
            print(f'{f}:{i}: trailing whitespace')
            ok = False
sys.exit(0 if ok else 1)
\"";
              files = "\\.zig$";
              pass_filenames = false;
            };
          };
        };
      in
      {
        checks = {
          # Pre-commit hooks (formatting, linting)
          inherit pre-commit-check;

          # Unit tests
          test = pkgs.stdenv.mkDerivation {
            pname = "oci-test";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build test
              touch $out
            '';
          };

          # Fuzz targets (run corpus as regular tests)
          fuzz = pkgs.stdenv.mkDerivation {
            pname = "oci-fuzz";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build fuzz
              touch $out
            '';
          };

          # Zig formatting check
          fmt = pkgs.stdenv.mkDerivation {
            pname = "oci-fmt";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig fmt --check src/
              touch $out
            '';
          };

          # Build check (ensure library compiles)
          build = pkgs.stdenv.mkDerivation {
            pname = "oci-build";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build
              touch $out
            '';
          };
        };

        devShells.default = pkgs.mkShell {
          inherit (pre-commit-check) shellHook;

          buildInputs = with pkgs; [
            zig
            zls
            valgrind
          ];
        };
      }
    );
}
