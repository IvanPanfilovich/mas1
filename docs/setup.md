# Project setup

## Requirements

Use Python 3.11+, a current Codex or Claude Code client, and an authenticated account with a working model. The installer needs only Python's standard library. Ledger checks additionally use `jsonschema`; install `requirements.txt` into a virtual environment.

The installer is local to an existing target project. No provider keys, account settings, global agent configuration, or sessions are copied.

## Install

```bash
python3 scripts/verify.py
python3 scripts/install.py --target /absolute/path/to/project --runtime both
python3 scripts/install.py --target /absolute/path/to/project --runtime both --apply
```

`--runtime codex` installs `.codex/agents/mas1_portable_*.toml` and a marked `AGENTS.md` block. `--runtime claude` installs `.claude/agents/mas1-portable-*.md` and a marked `CLAUDE.md` block. Both copy the portable prompt, compatibility guide and templates to `.mas1-system/`.

Review existing instructions for conflicts, particularly an existing canonical `MAS1` trigger. Use the explicit phrase **MAS1 portable** for this installation. Do not let a portable trigger replace a canonical compliance requirement.

The installer previews every planned write, refuses symlink destinations and conflicting managed files, backs up an existing instruction file before appending, and writes a receipt. Rerunning an identical install is a no-op. It refuses instructions changed inside its marked block. There is deliberately no force overwrite flag. Supply a canonical target path: on macOS, aliases such as `/tmp` and `/var` are symlinks; use their resolved `/private/...` path.

Open a new session in the project. Confirm roles are actually available using your client's agent UI/commands and run a small read-only task first. Configuration files alone do not prove live loading or model selection. Choose account-supported models if you customize roles; record the change. Portable profiles inherit the parent model by default.

Codex custom agents are standalone TOML files in `.codex/agents/`. See [official Codex subagents documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents). Existing global settings may disable delegation; inspect them rather than overwriting your configuration.

Claude Code uses Markdown with YAML frontmatter in `.claude/agents/`. See [official Claude subagents documentation](https://code.claude.com/docs/en/sub-agents) and [project instructions](https://code.claude.com/docs/en/memory). Read-only Claude roles expose only Read, Glob and Grep. This is a restricted tool surface, not an OS security boundary. Workers get Bash for checks as well as editing tools; host permissions still apply.

## Rollback

Inspect `.mas1-system/install-receipt.json`. Delete only the installed paths whose bytes still match the receipt, remove the exact marked instruction block, and restore an instruction backup if appropriate. Keep any edits or user-created files you want. The installer does not auto-uninstall because a later session may have changed those files. The source repository and global settings are untouched.

## Share with a team

Review installed instruction blocks and role files before committing them to your target repository. Ignore `.mas1-system/backups/` and the local receipt because backups may contain project instructions. Do not commit `.mas1/tasks/` by default: findings and evidence can contain private project data.
