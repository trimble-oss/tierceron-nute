## License
[LICENSE](LICENSE)

# Tierceron-nute

[![GitHub release](https://img.shields.io/github/release/trimble-oss/tierceron-nute.svg?style=flat-square)](https://github.com/trimble-oss/tierceron-nute/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/trimble-oss/tierceron-nute)](https://goreportcard.com/report/github.com/trimble-oss/tierceron-nute)
[![PkgGoDev](https://img.shields.io/badge/go.dev-docs-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/trimble-oss/tierceron-nute)

## What is it?
Tierceron-nute contains the interactive UI, rendering, and mashup application layer of Tierceron. It combines the shared mashup SDK with multiple GUI and rendering front ends plus runnable examples.

## What is in this repo?
- `mashupsdk`: client and server packages plus GUI bootstraps for G3N, Fyne, Gio, and Go Mobile.
- `g3nd`: 3D rendering and display packages including `worldg3n`, `g3nrender`, `g3ndisplay`, `g3nmash`, palette, and data helpers.
- `fyne`: Fyne-based UI support.
- `custos`: mashup application packages such as `custosworld`.
- `examples/helloworld`: runnable Fyne, custos, and mobile examples.
- `proximus/ebit`: an Ebiten-based entrypoint.
- `tls`: certificate helpers for local examples and mashup demos.

## Key Features
- Multiple GUI front ends in one module: G3N, Fyne, Gio, Go Mobile, and Ebiten-based experiments.
- Shared mashup client and server bootstrap packages for wiring applications.
- Example applications under `examples/helloworld` for validating local setup.
- Optional rendering support for both interactive and headless runs.

## Getting started
To work with the module locally:

- Run `go mod download`.
- Install `protoc` if you need to regenerate gRPC assets: https://grpc.io/docs/protoc-installation/
- Build the common SDK components with `make mashupsdk`.
- On Linux, install the G3N support libraries with `sudo apt-get install xorg-dev libgl1-mesa-dev libopenal1 libopenal-dev libvorbis0a libvorbis-dev libvorbisfile3 libxkbcommon-x11-dev libx11-xcb-dev`.
- For local example certificates, run `./certs_gen.sh` from `mashupsdk/tls/` and place the generated files under `examples/helloworld/hellocustos/tls`.
- Build examples such as `make hellocustosworld`, `make helloworldgio`, or `make helloworldfyne`.

## Trusted Committers
- [Joel Rieke](mailto:joel_rieke@trimble.com)
- [David Mkrtychyan](mailto:david_mkrtychyan@trimble.com)
- [Karnveer Gill](mailto:karnveer_gill@trimble.com)
- [Meghan Bailey](mailto:meghan_bailey@trimble.com)

## Code of Conduct
Please read [CODE_OF_CONDUCT.MD](CODE_OF_CONDUCT.MD) before contributing or opening issues.

## Security
Please review [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.
