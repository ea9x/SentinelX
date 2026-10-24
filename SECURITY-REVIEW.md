# Security review — 2026-10-22

This review covers the local deployment, source, isolated regression tests, and package advisories. It does not certify the application as vulnerability-free or production-ready.

## Applied controls

Authentication attempts have database-backed per-peer-IP fixed-window limits. Untrusted Origin headers are rejected for mutations, request bodies are capped at 64 KB, API responses are not cached, and security headers are added. Public registration is disabled by default; existing users remain enabled. To intentionally enable registration for a trusted environment set ALLOW_REGISTRATION=true in backend/.env.

JWT cookies are HttpOnly with CSRF checks, and credentials changes/logout revoke sessions. Weak signing keys fail startup. Avatar retrieval requires the owning user. Report errors no longer return exception text.

Updated frontend lockfile and Python requirements address known package advisories. Rate-limit records share the application database and survive service restarts. Reverse proxies are not implicitly trusted: peers behind a proxy share its rate limit unless a separately reviewed trusted-proxy setup is deployed.

## Deployment boundaries

The application intentionally allows trusted analysts to scan private/local targets. Authentication and closing public registration reduce access, but do not provide per-destination egress policy, DNS-rebinding defense or authorization verification for networks. Do not expose it as a public multi-tenant scanning service without a scanner sandbox, explicit destination allowlists and network egress controls. External tool redirects and template behavior require separate review.

The current local HTTP deployment has Secure cookies disabled and uses Flask development serving and Vite preview. Internet deployment requires TLS, Secure cookies, a production server/reverse proxy, CSP verification, restricted firewall rules, monitoring, and a separate external penetration test. Docker now requires explicit randomly generated keys/passwords. Existing Docker database credentials must be changed in the database as well; changing environment variables alone does not rotate an existing volume.

SQLAlchemy binds query parameters. Scan commands use argument arrays rather than shell=True, and target input is constrained. React renders textual findings without dangerouslySetInnerHTML; PDF text is escaped. These code paths were reviewed and bounded negative tests were added; this is not proof that every injection path is absent. No active scanner attack was run against the real user database or networks.

Security references: https://flask.palletsprojects.com/en/stable/web-security/ and https://vite.dev/guide/static-deploy.html .

## Source preparation — 2026-10-23

Source-only packaging excludes private installation state and third-party runtimes. Environment templates ship no secrets or default accounts. Local supervision restarts only a backend whose port is closed; it is not a high-availability or monitoring certification. CI is configured but hosted results require an actual push. Docker changes remain unverified by a complete build/run in this preparation. Password and email changes invalidate outstanding reset links.
