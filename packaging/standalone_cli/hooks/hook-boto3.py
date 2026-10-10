"""Retain Botocore session paths and bundle boto3's resource definitions.

This hook replaces PyInstaller's own boto3 hook, so it must also collect what
that one did: ``boto3.resource("ec2")`` reads ``boto3/data/<service>/<version>/
resources-1.json`` at run time, and without them every resource call fails with
"The 'ec2' resource does not exist".
"""

from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("boto3", includes=["data/**/*.json"])
hiddenimports = ["botocore.credentials", "botocore.session"]
