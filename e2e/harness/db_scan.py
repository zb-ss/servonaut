"""A box with two web apps' DB credentials, as the read-only scan sees it.

Servonaut discovers DB credentials by running one read-only command over
SSH that finds known config files and prints each behind a ``===FILE:``
marker. :func:`script_db_scan` makes the fake ``ssh`` answer that command
for one host with a Joomla ``configuration.php`` and a Laravel ``.env``.
The passwords are fabricated; journeys assert they never leave the secret
store in the clear.
"""

from __future__ import annotations

from e2e.harness.artifacts import register_secret
from e2e.harness.fleet import AwsHost
from e2e.harness.shims import ShimSet

FILE_MARKER = "===FILE:"
SHOP_PASSWORD = "fabricated-shop-pass-6a1f"
BLOG_PASSWORD = "fabricated-blog-pass-e20c"

SCAN_OUTPUT = (
    f"{FILE_MARKER}/var/www/shop/configuration.php===\n"
    "<?php\n"
    "class JConfig {\n"
    "\tpublic $dbtype = 'mysqli';\n"
    "\tpublic $host = 'localhost';\n"
    "\tpublic $user = 'shop';\n"
    f"\tpublic $password = '{SHOP_PASSWORD}';\n"
    "\tpublic $db = 'shop';\n"
    "}\n"
    f"{FILE_MARKER}/srv/blog/.env===\n"
    "DB_CONNECTION=pgsql\n"
    "DB_HOST=10.0.2.31\n"
    "DB_PORT=5432\n"
    "DB_DATABASE=blog\n"
    "DB_USERNAME=blog\n"
    f"DB_PASSWORD={BLOG_PASSWORD}\n"
)


def script_db_scan(shims: ShimSet, host: AwsHost) -> None:
    """Answer the credential scan on *host* (reached on its public address)."""
    register_secret(SHOP_PASSWORD, BLOG_PASSWORD)
    address = (host.public_ip or host.private_ip or "").replace(".", r"\.")
    shims.when("ssh", f"{address}.*{FILE_MARKER}", stdout=SCAN_OUTPUT)
