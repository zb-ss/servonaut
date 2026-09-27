"""Make gi.repository.WebKit2 a run-time module so its hook runs.

Modules loaded through the GObject repository are missing to PyInstaller's
analysis. PyInstaller converts the namespaces it knows, but not this one.
"""


def pre_safe_import_module(api):
    api.add_runtime_module(api.module_name)
