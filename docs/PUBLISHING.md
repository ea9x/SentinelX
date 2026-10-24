# Publishing the source

Publish only the prepared source folder, never the original installation directory. The installation includes private configuration, scanner runtimes, backups, generated reports and historical working files.

1. Decide whether the repository should be private or public and choose a license for code you own. This package deliberately does not guess a license.
2. Run `python scripts/check_release.py`, backend tests, frontend translation tests and the frontend build. Check every staged filename with `git diff --cached --name-only` before a commit.
3. Keep both `.env.example` files blank for secrets. Generate private values locally with `scripts/configure_local.py`. Do not add generated configuration to Git.
4. Review dependency licenses and enable GitHub private vulnerability reporting and secret scanning where available. Do not claim these are enabled merely because this document exists.
5. Create a new empty GitHub repository, then follow GitHub's displayed remote/push instructions from the clean source folder. Do not reuse another project's history or paste account tokens into scripts.
6. Inspect hosted Actions results. Local checks do not prove that GitHub-hosted CI or Docker passed. No release, repository or external upload is created by the local preparation scripts.

If you have ever pushed secrets, revoke/rotate them before following GitHub's history-cleanup process. `.gitignore` cannot remove already committed files.
