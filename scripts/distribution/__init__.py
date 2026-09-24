"""Distribution packaging and release manifest assembly scripts.

Import the packaging and signing tools from their own submodules (for example
``scripts.distribution.package_deb``). Re-exporting their functions here would
replace the submodule attributes of the same name on this package.
"""

from scripts.distribution.release_candidate import channel_for_tag

__all__ = ["channel_for_tag"]
