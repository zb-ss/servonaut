"""Bundle only the Soup 3.0 typelib; the host provides its library and data.

Replaces PyInstaller's own hook, which would also copy the library.
"""

from PyInstaller.utils.hooks.gi import GiModuleInfo


def hook(hook_api):
    module_info = GiModuleInfo("Soup", "3.0")
    if not module_info.available:
        return
    _host_libraries, typelibs, hiddenimports = module_info.collect_typelib_data()
    hook_api.add_datas(typelibs)
    hook_api.add_imports(*hiddenimports)
