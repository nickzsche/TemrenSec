# Integrations

Temren ships with first-class integrations for the most-requested tools. Each is
configurable via the `/dashboard/settings → Integrations` tab or via environment
variables for headless deployments.

## Issue trackers

### Jira

```bash
export TEMREN_JIRA_HOST=acme.atlassian.net
export TEMREN_JIRA_EMAIL=ops@acme.com
export TEMREN_JIRA_TOKEN=...           # API token, not password
export TEMREN_JIRA_PROJECT=SEC
```

Behaviour: every finding with severity ≥ MEDIUM opens a Jira issue. Severity drives
the priority field. Duplicate findings update the existing issue rather than re-creating.

### GitHub Issues

```bash
export TEMREN_GH_TOKEN=ghp_…           # needs `repo` scope
export TEMREN_GH_REPO=acme/payments
```

PR comments on `pull_request_target` events summarise findings in the PR.

### GitLab

Same shape as GitHub; use `TEMREN_GL_*` env vars.

### DefectDojo

```bash
export TEMREN_DOJO_URL=https://dojo.acme.internal
export TEMREN_DOJO_KEY=...
```

## Chat / paging

| Channel    | Env var(s)                                  |
|------------|---------------------------------------------|
| Slack      | `TEMREN_SLACK_WEBHOOK`                       |
| Discord    | `TEMREN_DISCORD_WEBHOOK`                     |
| Teams      | `TEMREN_TEAMS_WEBHOOK`                       |
| Mattermost | `TEMREN_MATTERMOST_WEBHOOK`                  |
| RocketChat | `TEMREN_ROCKETCHAT_WEBHOOK`                  |
| ntfy       | `TEMREN_NTFY_BASE`, `TEMREN_NTFY_TOPIC`       |
| Telegram   | `TEMREN_TG_TOKEN`, `TEMREN_TG_CHAT`           |
| Pushover   | `TEMREN_PUSHOVER_TOKEN`, `TEMREN_PUSHOVER_USER` |
| PagerDuty  | `TEMREN_PAGERDUTY_KEY`                       |
| OpsGenie   | `TEMREN_OPSGENIE_KEY`                        |
| Twilio SMS | `TEMREN_TWILIO_SID`, `TEMREN_TWILIO_TOKEN`, `TEMREN_TWILIO_FROM`, `TEMREN_TWILIO_TO` |
| Webhook    | `TEMREN_WEBHOOK_URL`, optional `TEMREN_WEBHOOK_SECRET` (HMAC-SHA256) |

Severity floors are configurable per channel. A common production pattern:

```
critical → pagerduty, slack
high     → slack, jira
medium   → jira
low      → digest email
info     → audit-log only
```

## Single Sign-On

OIDC and SAML are supported via `pkg/auth`. Configure with:

```
TEMREN_AUTH_PROVIDER=oidc
TEMREN_OIDC_ISSUER=https://auth.acme.com
TEMREN_OIDC_CLIENT_ID=…
TEMREN_OIDC_CLIENT_SECRET=…
```

## Secret managers (planned)

- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- 1Password Connect

Tracked under https://github.com/nickzsche/TemrenSec/issues?q=label%3Aintegration.
