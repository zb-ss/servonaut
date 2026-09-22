"""Collect pywebview assets and platform submodules."""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files("webview", includes=["js/**/*.js"])
hiddenimports = collect_submodules("webview")
