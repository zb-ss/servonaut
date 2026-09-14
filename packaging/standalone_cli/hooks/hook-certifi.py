"""Bundle the certificate authority bundle used by HTTP clients."""

from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("certifi", includes=["*.pem"])
