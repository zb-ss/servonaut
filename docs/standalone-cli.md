# Standalone CLI preview

Servonaut is preparing console-only standalone CLI archives for these preview
targets:

- Windows x64
- macOS Intel and Apple Silicon
- Ubuntu 22.04 and 24.04 x64

Each archive will include the base Servonaut CLI plus MCP, OVH, and Hetzner
support. Desktop rendering and all voice runtimes, speech engines, and models
are excluded.

Standalone archives use the same `~/.servonaut` configuration and data location
as pip and pipx installations. Their update and dependency handling is managed
by the frozen runtime rather than the system Python.

These archives are not installers, signed releases, or supported downloads
yet. Automated validation does not replace clean-machine testing on Windows
10/11 or macOS 13 Intel and Apple Silicon. Use the documented pipx or pip
installation until a signed public release is announced.
