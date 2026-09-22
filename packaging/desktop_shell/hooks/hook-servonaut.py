"""Package resources loaded by the desktop application at runtime."""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files(
    "servonaut",
    includes=["*.css", "*.tcss", "styles/**/*.tcss", "data/*.txt"],
)

hiddenimports = [
    *collect_submodules("servonaut.screens.settings.panels"),
    *collect_submodules("servonaut.desktop"),
]
