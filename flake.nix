{
  description = "OCI library for Zig - container image operations";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    oci-spec-zig = {
      url = "github:navidys/oci-spec-zig";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, pre-commit-hooks, oci-spec-zig }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        version = if (self ? shortRev) then self.shortRev else "dev";

        # Zig dependency hash must match build.zig.zon
        ociSpecHash = "ocispec-0.4.0-dev-voj0cey1AgDS-1Itn3Xu5AiWtB6cwMddZtDUssOtWrIn";

        # Pre-fetch zig deps for sandboxed builds
        zigDepsDir = pkgs.runCommand "oci-zig-deps" {} ''
          mkdir -p $out
          ln -s ${oci-spec-zig} $out/${ociSpecHash}
        '';

        pre-commit-check = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            zig-fmt = {
              enable = true;
              name = "zig fmt";
              entry = "${pkgs.zig}/bin/zig fmt";
              files = "\\.zig$";
              pass_filenames = false;
              args = [ "--check" "src/" ];
            };

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

        zigBuildArgs = "--system ${zigDepsDir}";

      in
      {
        checks = {
          inherit pre-commit-check;

          test = pkgs.stdenv.mkDerivation {
            pname = "oci-test";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build test ${zigBuildArgs}
              touch $out
            '';
          };

          fuzz = pkgs.stdenv.mkDerivation {
            pname = "oci-fuzz";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build fuzz ${zigBuildArgs}
              touch $out
            '';
          };

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

          build = pkgs.stdenv.mkDerivation {
            pname = "oci-build";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build ${zigBuildArgs}
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
