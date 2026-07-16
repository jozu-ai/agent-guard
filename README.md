# Jozu Agent Guard

A secure runtime for AI coding agents. Jozu Agent Guard enforces what an agent can and can't do at the operating system level instead of relying on prompts. Every tool call and network access goes through a policy check before it's allowed to run.

Agents run inside a disposable Linux microVM with no access to your home directory, SSH keys, or credentials unless you grant it explicitly. Once the agent exits, the VM is thrown away.

Works with Claude Code, Gemini CLI, Codex CLI, and OpenClaw.

Runs on macOS with Apple Silicon (M1 or later) today. Linux and Windows support are on the roadmap.

## Documentation

Full documentation, including the quickstart, architecture, policy authoring, and operations guides, is at:

[jozu.com/docs/agent-guard](https://jozu.com/docs/agent-guard/getting-started/ag-overview.html)

## Download

Release binaries, checksums, SBOMs, and license notices are published on the [Releases](../../releases) page of this repository.

## Support

Found a bug or have a question? Open an [issue](../../issues) here.

## License

Jozu Agent Guard is proprietary software distributed by Jozu, Inc. See [NOTICE](NOTICE) for details on third-party components included in the distribution.
