# MCP Registry Listing

Servonaut's MCP server is listed in the [official MCP Registry](https://registry.modelcontextprotocol.io)
as **`dev.servonaut/servonaut`**, so MCP clients and registry aggregators can
discover and install it directly.

## How the listing works

- [`server.json`](../server.json) at the repo root is the registry manifest.
  It describes the PyPI package, the stdio transport, and the launch command
  (`uvx --from 'servonaut[mcp]' servonaut --mcp`).
- The README contains an `mcp-name` marker (an HTML comment near the top)
  that the registry uses to verify PyPI package ownership. Don't remove it.
- The `dev.servonaut` namespace is verified via a DNS TXT record on
  `servonaut.dev` (Ed25519 public key, `v=MCPv1` format).

## Publishing flow

Registry publishing is automated in `.github/workflows/publish.yml`
(`mcp-registry` job). On each GitHub release it:

1. Sets the version in `server.json` from the release tag (the committed
   version is informational only).
2. Waits until PyPI serves the new package version (the registry validates
   the package exists and its README carries the `mcp-name` marker).
3. Authenticates with `mcp-publisher login dns` using the `MCP_PRIVATE_KEY`
   repository secret and publishes the manifest.

No manual step is needed for a normal release. To publish manually, install
[`mcp-publisher`](https://github.com/modelcontextprotocol/registry/releases),
authenticate the same way, and run `mcp-publisher publish` from the repo root.
