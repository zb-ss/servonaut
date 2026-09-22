"""Retain the stdio MCP transport and its pinned schema-format fallback."""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

hiddenimports = [*collect_submodules("mcp.server"), "rfc3987_syntax"]
# jsonschema imports this installed fallback after the optional legacy rfc3987
# package is unavailable. Its parser opens this grammar by package-relative path.
# The pinned grammar has no imports; PyInstaller's upstream Lark hook retains
# Lark's own grammar resources.
datas = collect_data_files("rfc3987_syntax", includes=["syntax_rfc3987.lark"])
