"""Package resources loaded by the console application at runtime."""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files(
    "servonaut",
    includes=["*.css", "*.tcss", "styles/**/*.tcss", "data/*.txt"],
)

# Settings panels are intentionally imported lazily from the static registry so
# one unavailable panel does not prevent the settings shell from opening.
# Keep this limited to the panel package: the standalone policy excludes the
# optional voice runtime and its native dependencies.
hiddenimports = collect_submodules("servonaut.screens.settings.panels")
