"""Local QA sandbox: the end-to-end suite's fakes, kept running for manual walks.

Run ``python -m e2e.sandbox --help`` from a checkout, and see "Local QA
sandbox" in CONTRIBUTING.md. Nothing is imported here: textual-pilot-mcp
imports this package on its way to ``tpmcp_spec.py``, and that import must
not load anything from the checkout.
"""
