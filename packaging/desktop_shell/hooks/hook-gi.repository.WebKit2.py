"""Bundle only the WebKit2 4.1 typelib; the host provides its library and data.

PyInstaller has no hook of its own for it.
"""

from PyInstaller.utils.hooks.gi import GiModuleInfo


def hook(hook_api):
    module_info = GiModuleInfo("WebKit2", "4.1")
    if not module_info.available:
        return
    _host_libraries, typelibs, hiddenimports = module_info.collect_typelib_data()
    hook_api.add_datas(typelibs)
    hook_api.add_imports(*hiddenimports)
