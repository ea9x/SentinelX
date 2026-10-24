# Changelog

## Unreleased — v0.1.1 preparation

- Extend local recovery to the frontend while leaving occupied/unrecognized ports untouched.
- Add guided Windows setup with a SQLite local trial and existing-MySQL option.
- Preserve existing configuration/accounts, use hidden MySQL password prompts, and report missing scanner tools.
- Skip the MySQL startup wait in SQLite mode and label database health accurately.

- Prepare a source-only distribution with configuration templates, publishing checks and CI.
- Add a conservative Windows backend supervisor and document its stop procedure.
- Remove the shared built-in ZAP API key fallback; installations must configure their own key.
- Preserve review revisions and classification in scan details; show translated finding types.
- Invalidate outstanding password reset links after password/email changes.
- Distinguish unavailable login services from rejected credentials.

This is development history, not an announcement of a production-ready release.
