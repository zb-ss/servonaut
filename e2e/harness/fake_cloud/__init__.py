"""FakeCloud: a local HTTPS stand-in for the Servonaut API and the package index.

Import :mod:`e2e.harness.fake_cloud.app` for the server; this package module
stays import-light because the bootstrap loads :mod:`.tls` before anything
else.
"""
