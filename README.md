# Jozu Agent Guard

A secure runtime for AI coding agents. Jozu Agent Guard enforces what an agent can and can't do at the operating system level instead of relying on prompts. Every tool call and network access goes through a policy check before it's allowed to run.

Agents run inside a disposable Linux microVM with no access to your home directory, SSH keys, or credentials unless you grant it explicitly. Once the agent exits, the VM is thrown away.

Works with Claude Code, Gemini CLI, Codex CLI, and OpenClaw.

Runs on macOS with Apple Silicon (M1 or later) today. Linux and Windows support are on the roadmap.

## Install

No GitHub account, no extra tooling, no authentication:

```bash
curl -fsSL https://raw.githubusercontent.com/jozu-ai/agent-guard/main/scripts/install.sh | bash
```

The script downloads the release binary (about 550 MB) and refuses to install it unless it carries Jozu's Apple Developer ID signature. When the release publishes a `checksums.txt`, the SHA-256 is checked as well and a mismatch also aborts the install. The signature is the gate that always applies; the checksum is defense in depth on top of it.

Where it lands, in order: `/usr/local/bin` if you can already write there, then `~/.local/bin` if that is on your PATH, otherwise `/usr/local/bin` with a sudo prompt. The fallback is `/usr/local/bin` because it is the only one of the two on macOS's stock PATH (see `/etc/paths`), so installing anywhere else unasked could leave you with a binary your shell cannot find. Set `INSTALL_DIR` to install elsewhere, or `VERSION` to pin a specific release:

```bash
VERSION=v0.7.1 curl -fsSL https://raw.githubusercontent.com/jozu-ai/agent-guard/main/scripts/install.sh | bash
```

If the machine cannot reach github.com directly, re-host `agentguard` and `checksums.txt` on an internal server (https only) and point the script at them with `AGENTGUARD_BASE_URL`. The checksum and signature checks still apply.

Two limits to know before relying on an internal mirror. The location is not remembered: it applies to the install that used it, and `agentguard update` still expects to reach this repository's Releases page. And verification pins Jozu's signing identity rather than a version, so a mirror left stale keeps serving whatever signed release it holds.

Once installed, `agentguard update` installs later releases in place.

## Documentation

Full documentation, including the quickstart, architecture, policy authoring, and operations guides, is at:

[jozu.com/docs/agent-guard](https://jozu.com/docs/agent-guard/getting-started/ag-overview.html)

## Download

Release binaries, checksums, SBOMs, and license notices are published on the [Releases](../../releases) page of this repository.

## Support

Found a bug or have a question? Open an [issue](../../issues) here.

## License

Jozu Agent Guard is proprietary software distributed by Jozu, Inc. See [NOTICE](NOTICE) for details on third-party components included in the distribution.
