# Contributing

Open an issue with a concrete failure mode, reproduction, affected workflow/adapter, and proposed acceptance criteria. Do not paste private ledgers, credentials, customer material, or full client transcripts.

For a change, run `python3 scripts/check.py`. Keep provider-specific behavior in adapters. Preserve the canonical prompt and reference-profile hashes unless deliberately importing a verified new upstream source revision; update provenance and version together. Do not weaken the validator's model, lifecycle or invalidated-cutover checks to make a portable run pass.

Use separate revisions for the source protocol, public distribution, and portable adaptation. Explain behavioral changes, compatibility, checks and limitations in pull requests. Public tests must not depend on the author's filesystem or private project data.

After editing distributable files, regenerate checksums with `python3 scripts/manifest.py`, then rerun checks. The manifest excludes Git metadata, local caches/environments, and itself. Synthetic examples must be labeled synthetic and must never imply real execution, tokens or independent review.
