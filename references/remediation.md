# Remediation map

Each row maps a TruffleHog detector to the exe.dev integration that replaces the secret. Read the linked doc for current commands before acting.

Integration basics ([overview](https://exe.dev/docs/integrations.md)): create with `integrations add`, attach with `integrations attach` (directly, by tag, or with auto-attach; see [attaching](https://exe.dev/docs/integrations-attach.md)). Stored secrets show as `***` in `integrations list --json`, and the VM never sees them.

| Detector(s) | Replace with | Doc |
| --- | --- | --- |
| Github, GithubApp, GitHubOauth2 | GitHub integration | [integrations-github](https://exe.dev/docs/integrations-github.md) |
| AWS, AWSSessionKey | AWS workload identity federation | [integrations-aws-wif](https://exe.dev/docs/integrations-aws-wif.md) |
| GCP, GCPApplicationDefaultCredentials | GCP workload identity federation | [integrations-gcp-wif](https://exe.dev/docs/integrations-gcp-wif.md) |
| Anthropic | Anthropic workload identity federation, or the LLM integration | [integrations-anthropic-wif](https://exe.dev/docs/integrations-anthropic-wif.md), [integrations-llm](https://exe.dev/docs/integrations-llm.md) |
| OpenAI, OpenAIAdmin | OpenAI workload identity federation, or the LLM integration | [integrations-openai-wif](https://exe.dev/docs/integrations-openai-wif.md), [integrations-llm](https://exe.dev/docs/integrations-llm.md) |
| SlackWebhook | Slack integration (one-way) | [integrations-slack](https://exe.dev/docs/integrations-slack.md) |
| Slack (bot tokens) | Slack bot integration | [integrations-slack-bot](https://exe.dev/docs/integrations-slack-bot.md) |
| DiscordWebhook | Discord integration (one-way) | [integrations-discord](https://exe.dev/docs/integrations-discord.md) |
| DiscordBotToken | Discord bot integration | [integrations-discord-bot](https://exe.dev/docs/integrations-discord-bot.md) |
| Tailscale, TailscaleApiKey | Tailscale workload identity federation | [integrations-tailscale-wif](https://exe.dev/docs/integrations-tailscale-wif.md) |
| Docker, DockerHub | Container registry integration (quay.io, ghcr.io, atcr.io, pkg.dev) | [integrations-oci-registries](https://exe.dev/docs/integrations-oci-registries.md) |
| Postgres | Postgres database integration (`db:postgres`; still rolling out). Otherwise restrict file access and rotate | [integrations-catalog](https://exe.dev/docs/integrations-catalog.md) |
| MongoDB, Redis, JDBC, SQLServer, URI | No integration. Restrict file access, rotate the password, consider an egress policy | [internet-access](https://exe.dev/docs/internet-access.md) |
| PrivateKey | No integration. Rotate it; for SSH into VMs use VM-scoped keys | [vm-scoped-ssh-keys](https://exe.dev/docs/vm-scoped-ssh-keys.md) |
| ~125 service detectors (Stripe, Datadog, Cloudflare, Hugging Face, ...) | Catalog integration for that service; `scripts/catalog.json` has the mapping | [integrations-catalog](https://exe.dev/docs/integrations-catalog.md) |
| Anything else with an HTTP API | HTTP proxy header injection, or token-mint for short-lived tokens | [integrations-http-proxy](https://exe.dev/docs/integrations-http-proxy.md), [integrations-token-mint](https://exe.dev/docs/integrations-token-mint.md) |

## Notes

- **Database URIs**: Postgres-wire databases (generic Postgres, Neon, Supabase, CockroachDB) have `db:` integrations that broker the connection so the password stays off the VM; they are still rolling out, so not every account has them. Other databases (MongoDB, Redis, ...) have no integration equivalent. Restrict who can read the file, rotate the password, and consider an [egress policy](https://exe.dev/docs/internet-access.md).
- **Git history**: removing a secret from the current file does not remove it from history. Rotate it, and rewrite history only if the repo is shared.
