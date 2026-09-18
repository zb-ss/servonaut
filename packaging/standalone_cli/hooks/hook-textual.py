"""Retain Textual's stylesheet resources without collecting unrelated extras."""

from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("textual", includes=["*.css", "*.tcss"])
