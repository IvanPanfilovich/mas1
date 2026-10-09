# Use in ChatGPT and Claude

1. Paste or attach `prompts/MAS1-portable.md` and `prompts/chat-starter.md`.
2. Replace the task placeholders. Include relevant requirements and source material.
3. Ask the assistant to state available capabilities before choosing depth.
4. Require evidence for claims and a final distinction between review, implementation, and readiness.

If your client supports persistent project instructions/files, store the portable workflow there and add a short instruction to read it when you request MAS1 portable. Otherwise paste it into each new conversation. Upload support, context limits and tools vary by client and account; check that the assistant can actually read the file.

A normal conversation may have neither project filesystem access nor executable checks. It can critique a plan and produce a patch or checklist, but it must not claim that it changed your repository or passed tests. A named internal critic is not an independent agent.

ChatGPT Work exposes subagent workflows to eligible accounts; actual capabilities and routing must be checked in the session. See [official subagent guidance](https://learn.chatgpt.com/docs/agent-configuration/subagents). Claude Code has native custom subagents; a Claude conversation should only claim delegation if the client actually exposes it. See [Claude Code subagents](https://code.claude.com/docs/en/sub-agents).

Do not use the original canonical prompt in a Claude-only chat and claim its model-pinned gates were satisfied. Use the explicitly labeled adaptation. For tasks needing mandatory independent review or execution evidence that the chat cannot supply, finish the safe analysis and identify the missing step.
