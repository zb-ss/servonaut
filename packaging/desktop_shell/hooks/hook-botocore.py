"""Bundle Botocore's dynamically selected service models."""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files("botocore", includes=["data/**/*.json", "data/**/*.gz"])
hiddenimports = collect_submodules("botocore.data")
