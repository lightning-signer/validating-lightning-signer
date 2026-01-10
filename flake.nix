{
  description = "VLS nix development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
  };

  outputs = { self, nixpkgs, flake-utils, naersk }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # build rust application :)
        naersk' = pkgs.callPackage naersk { };

        vlsd = naersk'.buildPackage {
          pname = "vlsd";
          src = ./.;
          cargoBuildOptions = opts: opts ++ [ "-p" "vlsd" ];
          nativeBuildInputs = with pkgs; [ pkg-config protobuf ];
          buildInputs = with pkgs; [ openssl ];
        };

        vls-proxy = naersk'.buildPackage {
          pname = "vls-proxy";
          src = ./.;
          cargoBuildOptions = opts: opts ++ [ "-p" "vls-proxy" ];
          nativeBuildInputs = with pkgs; [ pkg-config protobuf ];
          buildInputs = with pkgs; [ openssl ];
        };

        vls = pkgs.symlinkJoin {
          name = "vls";
          paths = [ vlsd vls-proxy ];
        };
      in
      {
        packages = {
          vlsd = vlsd;
          vls-proxy = vls-proxy;
          vls = vls;
          default = vls;
        };

        # FIXME: will be good to have this formatting also the rust code
        formatter = pkgs.nixpkgs-fmt;

        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs; [ gnumake rustup openssl openssl.dev protobuf ];
          shellHook = ''
            export HOST_CC=gcc
            export RUST_BACKTRACE=1
          '';
        };
      }
    );
}
