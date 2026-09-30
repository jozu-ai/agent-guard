# Jozu Agent Guard

A secure runtime for AI coding agents. Jozu Agent Guard enforces what an agent can and can't do at the operating system level instead of relying on prompts. Every tool call and network access goes through a policy check before it's allowed to run.

Agents run inside a disposable Linux microVM with no access to your home directory, SSH keys, or credentials unless you grant it explicitly. Once the agent exits, the VM is thrown away.

Works with Claude Code, Gemini CLI, Codex CLI, and OpenClaw.

Jozu Agent Guard comes in two forms. The runtime above runs an agent you launch with `agentguard run` inside a microVM. The [Agent Guard Policy Gateway](#agent-guard-policy-gateway-macos) covers the AI apps you already use on your Mac, such as the ChatGPT and Claude desktop apps and browsers, by checking their traffic to AI providers against the same kind of policies.

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

## Agent Guard Policy Gateway (macOS)

The Agent Guard Policy Gateway enforces guardrail policies on the AI apps running on your Mac. It sits between those apps and the AI providers they talk to. Each request is checked against your policies before it leaves the machine, and a request that breaks a rule is blocked or has the sensitive part masked.

Use the gateway for apps you run directly on your Mac. Use `agentguard run` when you want an agent isolated in a microVM. The two work together.

### Install

The gateway ships as a signed and notarized installer, `AgentGuard.pkg`, on the [Releases](../../releases) page. It is separate from the CLI install script above, which installs only the `agentguard` binary. The installer includes the CLI, so you do not need both.

1. Download `AgentGuard.pkg` from the latest release.
2. Open it and follow the prompts, or run `sudo installer -pkg AgentGuard.pkg -target /`.
3. Approve the network extension when macOS asks. On a Mac that is not centrally managed, open System Settings, then General, then Login Items & Extensions, then Network Extensions, and turn on AgentGuard. Until you do, the gateway runs but inspects nothing, and `agentguard gateway status` reports capture as NOT ACTIVATED.
4. Reopen your AI apps. Apps that were already running when the gateway started are quit and reopened for you, because their existing connections bypass it. Claude Code sessions and Firefox need a restart too.

The installer places `agentguard` and `gerty` in `/usr/local/bin`, `AgentGuardGateway.app` and `AgentGuardDashboard.app` in `/Applications`, and a background service that runs as root. It adds the gateway's local certificate authority to the System keychain so that intercepted connections verify, and it starts a status-bar dashboard at login. It fetches the default policy, `jozu.ml/jozu/agentguard-reference-policy:v2`, on first install. Managed fleets use the same package with MDM configuration profiles.

Requires macOS 13 or later on Apple Silicon. QUIC traffic is only handled on macOS 15 and later (see Limits).

### Check that it is working

```bash
agentguard gateway status
```

The report shows whether the service is running, whether the certificate authority is trusted, how many policies are loaded, whether capture is active, which hosts are intercepted, and which apps are exempt. A value it cannot read is reported as "cannot determine", never as healthy. `agentguard gateway status --json` gives the same information for scripts. The status-bar dashboard shows the same state and lists recent allow, deny and redact decisions. To see decisions in a terminal, run `agentguard logs --guardrails`.

### What it covers

By default the gateway intercepts traffic to the Anthropic and OpenAI APIs, the Claude and ChatGPT web and desktop apps, and Google's Gemini APIs. Sign-in pages are left alone so that login keeps working. To stop inspecting a provider, pass `--exclude-host` to `agentguard gateway install`. Every exclusion is warned about and written to the audit log.

### Limits

The gateway reduces what reaches AI providers. It is not a complete guarantee, and you should know where it stops:

- Claude Code is exempt by default, so what the `claude` CLI sends is not inspected. Pass `--inspect-app com.anthropic.claude-code` to `gateway install` to inspect it.
- Connections opened before the gateway started are not inspected until the app reconnects.
- QUIC (HTTP/3) is blocked so clients fall back to TCP on macOS 15 and later. On macOS 13 and 14 it is neither blocked nor inspected, and `gateway status` says so.
- Traffic to a provider on a port other than 443, or where the destination name cannot be read, is passed through uninspected.
- Some clients carry their own certificate list and will not trust the gateway's certificate. The JVM is one: the installer adds the certificate to Java's trust store unless you pass `--no-java-trust`.
- File and image inspection is best effort. Unrecognised upload formats and bodies over 32 MiB are passed through.

### Hub reporting

Signing in to Jozu Hub is optional. Without it the gateway keeps enforcing policy and reports locally why it is not sending anything. When signed in, it sends a posture report every 5 minutes (health, versions, policy hash and refs) and audit records every 15 minutes (the decision, rule and policy, not the prompt text).

### Uninstall

```bash
sudo agentguard gateway uninstall --purge
```

This removes the certificate authority trust, the background service and the capture layer, and with `--purge` also the apps and the binaries the installer placed. Add `--dry-run` to see what would be removed first. Your policies and the audit trail are kept. A centrally managed install needs the maintenance token from your administrator (`--token`).

## Documentation

Full documentation, including the quickstart, architecture, policy authoring, and operations guides, is at:

[jozu.com/docs/agent-guard](https://jozu.com/docs/agent-guard/getting-started/ag-overview.html)

## Download

Release binaries, the `AgentGuard.pkg` installer, checksums, SBOMs, and license notices are published on the [Releases](../../releases) page of this repository.

## Support

Found a bug or have a question? Open an [issue](../../issues) here.

## License

Jozu Agent Guard is proprietary software distributed by Jozu, Inc. See [NOTICE](NOTICE) for details on third-party components included in the distribution.
