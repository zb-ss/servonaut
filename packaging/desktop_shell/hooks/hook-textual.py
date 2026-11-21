"""Freeze Textual's resources and modules resolved lazily by textual.widgets."""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files("textual", includes=["*.css", "*.tcss"])
# The runtime looks up widget modules by name, including re-export shims.
hiddenimports = collect_submodules("textual.widgets")
