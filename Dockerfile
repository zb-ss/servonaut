# Dockerfile for the Servonaut MCP server (stdio transport).
#
# Built so directories like Glama can start the server and run an
# introspection handshake (initialize + tools/list) without any cloud
# credentials — the tool catalogue is static, so `servonaut --mcp`
# answers introspection on a bare container. Live AWS/OVH/Hetzner calls
# still require credentials mounted at runtime; introspection does not.
#
#   docker build -t servonaut-mcp .
#   docker run --rm -i servonaut-mcp           # speaks MCP over stdio
FROM python:3.12-slim

WORKDIR /app

# Install the package with the MCP extra from the source tree.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[mcp]'

# stdio MCP server: clients (and Glama's introspector) talk over stdin/stdout.
ENTRYPOINT ["servonaut", "--mcp"]
