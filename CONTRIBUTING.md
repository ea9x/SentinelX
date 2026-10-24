# Contributing

Use an isolated environment and synthetic accounts/targets. Do not run active tests against other people's systems. Keep interface strings in English source with Arabic catalog entries, preserve API enum values, and never translate saved evidence.

Run backend unit/integration tests, frontend translation tests, the frontend build, and `python scripts/check_release.py`. Add regression coverage for security/behavioral fixes. Explain the trigger, before/after behavior, validation and remaining limitations in a pull request.

Keep scanner failure distinct from a successful empty result. Do not mark a finding fixed based only on its absence from a later scan. Do not commit credentials, screenshots of private data, generated reports or external scanner runtimes.

An open-source license and contributor licensing policy have not yet been selected. Discuss licensing with the owner before contributing substantial code; a pull request does not resolve copyright ownership automatically.
