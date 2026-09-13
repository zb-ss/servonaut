"""Minimal adapter for the checksum-pinned upstream terminal renderer."""

# Upstream registers WebGL and then replaces it with Canvas during open().
# Avoid initializing an unused GPU context on software-only native renderers.
WEBGL_REGISTRATION = (
    b"this.webglAddon=new p.WebglAddon,this.terminal.loadAddon(this.webglAddon),"
)


def canvas_renderer(source: bytes) -> bytes:
    """Remove only the redundant registration; reject an unexpected bundle."""
    if source.count(WEBGL_REGISTRATION) != 1:
        raise RuntimeError("Pinned renderer registration changed")
    return source.replace(WEBGL_REGISTRATION, b"", 1)
