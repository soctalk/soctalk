# Examples

Ready-to-load triage policies and response playbooks. They are the same
documents the no-code editors produce, so you can import one, watch it project
onto the pipeline in the editor's flow view, and adjust it before you activate.
Every authored policy and playbook starts in shadow mode: it is matched and
evaluated against live traffic for audit, enforcing nothing, until you promote
it.

Both surfaces are data run by deterministic interpreters. What you load here is
exactly what executes. See the concept docs for the full model:
[Triage policies](https://soctalk.github.io/soctalk-docs/triage-policies) and
[Response playbooks](https://soctalk.github.io/soctalk-docs/response-playbooks).

## Triage policies

Guardrails over the AI triage loop. The LLM proposes a disposition, the policy
disposes. The built-in safety floor (IOC and contradicted-authorization vetoes)
always applies and cannot be weakened. Authored guardrails can only make triage
stricter: an `override` raises a decision along `close → needs_more_info →
escalate`, an `interrupt` holds the draft for human review, and suppression is
not expressible. Lower `priority` wins; authored policies must sit at 60 or
above so the built-ins keep precedence.

**`triage-policies/pci-privileged-exec-strict.json`** owns sudo, su, and
sudoers alerts on the account authorization track. It requires the
authorization context step and the authorization engine before a verdict is
legal, and it lists PCI and PHI as close sign-off data classes. Three
guardrails: escalate when authorization is contradicted on a critical asset,
fall back to needs-more-info when verdict confidence is under 0.7, and interrupt
for human review when the asset is PCI-classified.

**`triage-policies/prod-critical-ioc-hardline.json`** owns IDS, web, and
authentication-failure alerts. It escalates when enrichment flags a known
malicious indicator, escalates when the alert correlates with an active
incident, and interrupts for human review when a production asset draws a
low-confidence verdict (under 0.6).

## Response playbooks

Procedural response dispatched after the triage disposition is final. A playbook
names vetted capabilities per disposition. Tier-0 actions (`annotate_investigation`,
`notify_webhook`) fire autonomously; an `external_action` is gated and routes to
a human-approved proposal before it executes. A `when` clause on an action makes
it conditional. Playbooks match on Wazuh rule groups and rule IDs or on ATT&CK
techniques and tactics.

**`response-playbooks/lateral-movement-endpoint-isolation.json`** matches ATT&CK
T1021 and the Lateral Movement tactic. On escalate it annotates the
investigation, notifies the webhook, and, when severity is at least 10, proposes
an EDR endpoint isolation for analyst approval. On close it annotates that
triage found no lateral-movement confirmation.

**`response-playbooks/privileged-account-compromise-notify.json`** matches sudo
and su rule groups and ATT&CK T1078. On escalate it notifies the webhook and,
when severity is at least 12, proposes an IAM account disable for analyst
approval. On close it annotates the investigation.

## Loading an example

In the UI, open **Triage Policies** or **Response Playbooks**, choose **New**,
and use **View as JSON** to paste a document in. The editor validates it
server-side and shows the flow projection. Save keeps it in shadow; activate it
from the list when you are ready for it to govern.

Over the API, POST the document to the tenant endpoint and then activate it:

```bash
# Triage policy
curl -sX POST \
  "$SOCTALK_URL/api/mssp/tenants/$TENANT_ID/triage-policies" \
  -H "Origin: $SOCTALK_URL" -H 'Content-Type: application/json' -b cookies.txt \
  -d "{\"definition\": $(cat examples/triage-policies/pci-privileged-exec-strict.json), \"status\": \"shadow\"}"

# Response playbook
curl -sX POST \
  "$SOCTALK_URL/api/mssp/tenants/$TENANT_ID/response-playbooks" \
  -H "Origin: $SOCTALK_URL" -H 'Content-Type: application/json' -b cookies.txt \
  -d "{\"definition\": $(cat examples/response-playbooks/lateral-movement-endpoint-isolation.json), \"status\": \"shadow\"}"
```

The response returns the stored record's `id`. Activate it with
`POST .../triage-policies/{id}/activate` or
`POST .../response-playbooks/{id}/activate`. Mutating calls need the `Origin`
header to match `SOCTALK_PUBLIC_ORIGIN`, and a session cookie from
`POST /api/auth/login`. Full API reference:
[REST API](https://soctalk.github.io/soctalk-docs/reference/api).
