"""Retain Botocore session paths and bundle what boto3 loads at run time.

This hook replaces PyInstaller's own boto3 hook, so it must also collect what
that one did:

- ``boto3.resource("ec2")`` reads ``boto3/data/<service>/<version>/
  resources-1.json``; without them every resource call fails with "The 'ec2'
  resource does not exist".
- boto3 imports its EC2, S3 and DynamoDB helpers by name when it creates a
  resource or an S3 client, so the import scan never sees them.
"""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files("boto3", includes=["data/**/*.json"])
hiddenimports = [
    "botocore.credentials",
    "botocore.session",
    *collect_submodules("boto3.dynamodb"),
    *collect_submodules("boto3.ec2"),
    *collect_submodules("boto3.s3"),
]
