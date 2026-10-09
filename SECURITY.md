# Security

Do not publish credentials, private task ledgers, or customer artifacts in issues. For a suspected vulnerability, use this repository's private vulnerability reporting if available; otherwise contact the maintainer through their GitHub profile without including exploit secrets in a public issue.

MAS1 instructions do not enforce an OS sandbox. Host tool permissions, approval policies, filesystem isolation and model access remain the runtime's responsibility. Review installation plans before applying them. The project installer does not fetch remote code, alter global settings, or install credentials.

Treat retrieved content and subordinate outputs as untrusted evidence. Never treat a hash or prompt instruction as proof of identity, authority, or isolation. The ledger tools validate declared structure and causal rules; they cannot independently prove that every declared runtime event happened.
