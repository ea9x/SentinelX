# Third-party components

SentinelX integrates separate projects and does not bundle their source, Windows runtimes or scanner executables in the source release. Install them from official distributions and preserve their notices. This list is an integration inventory, not a legal compatibility audit.

| Component | Role | Official source |
| --- | --- | --- |
| Nmap | Network/service discovery | https://nmap.org/ |
| WhatWeb | Web technology observations | https://github.com/urbanadventurer/WhatWeb |
| OWASP ZAP | Web assessment service | https://www.zaproxy.org/ |
| Nuclei | Template-driven checks | https://github.com/projectdiscovery/nuclei |
| SSLyze | TLS assessment | https://github.com/nabla-c0d3/sslyze |
| RubyInstaller | Optional Windows Ruby runtime | https://rubyinstaller.org/ |

Python dependencies are declared in `backend/requirements.txt`; JavaScript dependencies and their resolved packages are in `frontend/package-lock.json`. Each dependency has its own license. These notices do not grant a SentinelX license or replace upstream license requirements. Scanner results and templates may carry additional terms.
