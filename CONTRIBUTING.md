# Contributing

Contributions are welcome.

1. Keep all fixtures synthetic.
2. Do not commit real vaults, reports, credentials, tokens, internal paths, or screenshots.
3. Preserve the read-only and no-network defaults.
4. Add a focused regression test for every behavior change.
5. Run `PYTHONPATH=src python -m unittest discover -s tests -v` before opening a pull request.

Security-sensitive changes should explain the threat being addressed, the failure mode, and the test that proves the boundary.

