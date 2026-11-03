# Compliance evidence direction: brainstorm record

Session date: 2026-07-23. Status: brainstorm, no build commitment. Two
adversarial reviews shaped the conclusions. The pre-code gate is the QSA
falsification test described at the end.

## The question

Can soctalk deliver a lower-complexity value proposition for SMEs in regulated
markets by playing a compliance role instead of (or on top of) the SOC analyst
role, with the SOC as the data source?

## Where we landed, in one paragraph

Wazuh stays the foundation. The product direction is regulator-grade
*technical control evidence* built from data soctalk already collects and
judges: a deviation register, per-framework evidence packs with full
provenance, and a coverage ledger that makes the claims honest. It is sold
through the channel that controls the compliance outcome (QSAs, vCISOs,
MSPs/MSSPs), never marketed as a "compliance officer copilot". The MVP is a
set of free downloadable rules packs mapping unserved regulations (NIS2 first,
LGPD second) to Wazuh rules, which funnels Wazuh operators toward paid soctalk
tiers. Everything above rests on one enabling capability: an AI-assisted
mapping factory that turns a regulation into a validated framework pack in
days, with measured accuracy.

## Adversarial review outcomes

**Run 1 (compliance pivot): pursue modified.**

- The buyer is not the SME. Regulated SMEs delegate compliance trust to QSAs,
  vCISOs, MSPs and acquirers. Sell through them, as labor reduction.
- Auditors will not accept LLM-narrated claims as primary evidence. Artifacts
  must be source-backed: raw extracts, query manifests, scoped populations,
  period boundaries, version snapshots, hash manifests, exception register,
  human signoff. The LLM is assembler and narrator, never the evidence source.
- Wazuh compliance tags are relevance hints, not control evidence.
- Vanta/Drata/Sprinto are stronger than "checkbox collectors" (they pull
  MDM/EDR posture); differentiation is real only when narrowed to self-hosted,
  host-level, Wazuh-native technical evidence.
- True incremental build is a product slice, not a skin: compliance domain
  model, evidence provenance, scope tracking, exception workflow, exports,
  signoff flow.
- Kill shot: the deliverable is not accepted as audit-useful by whoever
  controls the compliance outcome. Cheapest falsification: hand-build evidence
  packs for 3 PCI controls from Wazuh data, show to ~3 QSAs and ~2 vCISO/MSP
  operators. No LOI, paid pilot, or channel pull afterward: park it.

**Run 2 (browser extension): pursue modified, demoted.**

- Kill shot: a screenshot does not prove a population. Auditors test
  completeness; a rendered page proves only what rendered. "Notarized
  screenshot" improves chain of custody, not population validity.
- "LLM reads any admin page" fails where it matters: pagination, lazy
  loading, virtual scroll, role filters, tenant variants, localization.
- Prior art is close (Vanta agentic evidence collection, Screenata, Strac,
  an AWS reference architecture). Not a secret wedge.
- The extension is the riskiest component in the buyer's eyes. If ever built:
  activeTab-only, operator reviews every capture, uploads pinned to the
  customer's own appliance, signed releases, SBOM.
- Verdict: last-mile capture helper for UI-only evidence gaps, fifth in build
  order. Fleet-wide extension (shadow SaaS): parked permanently, different
  company. Our refinement: guided capture should target the admin UI's own
  CSV/export download wrapped in a provenance packet, which answers the
  population objection while keeping reach into API-paywalled SaaS tiers.

## Strategic decisions settled

1. **Wazuh-anchored, not agentless-first.** A Wazuh-free entry product would
   compete head-on with the compliance-automation incumbents and expert shops
   with no structural advantage. The moat is self-hosted, host-level evidence
   plus the existing Wazuh install base as distribution. PCI scope (CDE) is
   small by design, so a scoped agent footprint is compatible with the
   low-complexity promise. Agentless items (read-only OAuth pulls for identity
   and cloud posture) survive only as supplements inside packs.
2. **Channel-first.** ICP: regulated org, or its MSP, that runs or will run
   Wazuh. The channel absorbs deployment work as billable service.
3. **Language discipline.** "Technical control evidence and deviation
   assessment", never "compliance copilot". LLM role stated as assembler over
   hash-manifested source evidence.
4. **Converged build order** (both review runs agree):
   1. Deviation/exception register (reuses authorization/expectedness
      verdicts and Engagements, closest to shipped product)
   2. PCI technical evidence pack (log review, FIM, SCA)
   3. Read-only OAuth supplements inside the pack
   4. Credentialed scans for API gaps
   5. Browser evidence camera as last-mile capture, export-first
   6. Fleet browser extension: never

## Prior art (verified 2026-07)

- Extension evidence capture: Screenata (closest to the "evidence camera",
  positioned as a Vanta/Drata accessory), Strac Evidence Agent, Vanta agentic
  evidence collection, AWS sample architecture.
- Extension-as-connector for no-API apps: Cerby (identity ops, proves the
  mechanism commercially).
- Fleet browser security: Push Security, LayerX ($45M), Island. Avoid.
- Chain-of-custody capture: Page Vault (their architecture keeps the human
  OUT of the chain of custody, an argument against capture in the operator's
  own browser).
- Discovery without endpoints: Nudge Security mailbox scanning.
- Wazuh + compliance: Wazuh's own dashboards (filtered alert views),
  SOCFortress CoPilot (SCA scorecards, CSV export), MSSPs hand-rolling report
  templates (Codesecure: 11 templates as managed-service labor). Nobody ships
  audit-period, provenance-grade evidence packs on Wazuh.
- Custom rules for new regulations: none found for LGPD, NIS2 or DORA.
  wazuh/wazuh#17602 is the demand signal; Wazuh's answer is the group-tag
  primitive, content left as an exercise.

## The MVP: rules packs as funnel

Free downloadable packs mapping unserved regulations to Wazuh rules, compiled
from ONE canonical mapping dataset into two outputs:

- Vanilla Wazuh: overlay XML appending custom group tags (`nis2_21.2b`),
  custom SCA policies (compliance keys are free-form YAML), dashboard
  saved-objects NDJSON as a pseudo-tab.
- soctalk: crosswalk tables joined at assessment time. Retroactive (a new
  framework maps over periods already collected), upgrade-safe, versioned.

Packs are free: distribution and lead generation, consistent with ecosystem
norms. Pack README states the vanilla limits honestly (tags apply
ingest-forward only, overlays are upgrade-fragile, a filtered dashboard shows
relevance, not posture); that statement is also the upsell. Monetization is
in soctalk tiers: posture insights (framework chips on investigations,
framework-filtered register, coverage checker), then evidence packs behind
the falsification gate. Optional later: paid "reviewed edition" of a pack
(same mapping, version-pinned, expert attestation letter, update SLA).

Framework order: NIS2 (largest unserved EU demand), LGPD (uncontested,
ANPD simplified regime fits SMEs, LatAm angle), DORA when a fintech pilot
pulls it. No PCI pack (natively tagged, no gap), PCI stays in the evidence
tier where the QSA channel lives.

## The mapping factory

The moat is not any single mapping (copyable) but the factory: regulation in,
validated pack out in days, maintained across ruleset upgrades.

Pipeline: structure both corpora (regulation articles + official crosswalks;
ruleset extracted to a pinned table of rule_id, description, groups,
compliance tags, plus SCA checks) → deterministic join first (control →
ISO 27002/800-53 via official crosswalks such as ENISA and NIST OLIR → rules
via existing `nist_800_53` tags; lineage auto-populated) → semantic gap-fill
(embeddings + temp-0 LLM proposing candidates with a constrained
`{evidences, claim, evidence_type}` output) → adversarial refutation pass per
mapping → structural asserts (base-rate envelope ~0.2-0.4 technical, fan-out
caps, sibling consistency, orphan lineage) → expert review of rationales for
the primary tier.

Calibration: blind-recovery test. Strip a natively-tagged framework's tags
(and scrub framework tokens from descriptions), remap from scratch, score
precision/recall against the official tags (strict and family-level). The
number is published with the pack. Claims are executable: every primary
mapping carries a canary spec (inject fixture, expect rule), run as mapping
goldens in the verify environment.

## Coverage is four separate claims

1. **Framework coverage** (static, per pack): controls classified as
   detection-evidenceable / config-evidenceable / needs-added-content /
   needs-non-Wazuh-source / not technical. Coverage stated against the
   addressable subset, with the honest denominator published.
2. **Mapping quality**: blind-recovery precision/recall, refutation survival,
   expert signoff rate.
3. **Deployment coverage** (per site, per period): population enrolled,
   keepalive continuity, prerequisite log sources present (a rule mapped to
   pgAudit is dormant without pgAudit forwarding), audit baseline verified by
   a meta-SCA policy, and synthetic canary injection proving each mapped
   pathway fires end to end (verify-skill methodology productized; itself
   evidence for "regularly testing effectiveness" duties).
4. **Evidence sufficiency** (per assessment): rubric floors enforced by a
   deterministic guard; failure yields `insufficient_evidence`, which is
   coverage telling the truth.

Product surface: the coverage ledger. Control rows, columns mapped → correct
→ deployable here → live this period → sufficient this period. Green across
all columns is the only meaning of "covered". The ledger doubles as gap
report, engagement tracker, subscription heartbeat and the first page a QSA
reads.

## Classification correctness

No ground truth exists for new frameworks, so correctness is a chain of
custody for the claim: derive rather than interpret (official crosswalk hops,
verbatim requirement quotes, never paraphrase), calibrate where ground truth
exists, check structure automatically, review rationales with compliance
professionals (not engineers), and stay falsifiable in the field (open packs,
errata process, disputes captured as data). Ship gate, mechanically: schema
invariants pass (primary tier requires derived lineage or named review),
structural asserts pass, blind-recovery within tolerance, primary canaries
green, zero unreviewed interpreted mappings in primary tier.

## Architecture in soctalk

- **No new LangGraph.** The single triage graph stays untouched. Compliance
  triage behavior arrives as data (triage policies, guardrails; the
  `close_signoff_data_classes=["pci"]` seam already exists).
- **The assessor is deliberately less agentic.** Per control: deterministic
  evidence assembly (recorded query manifests) → one-shot temp-0 LLM
  assessment (result enum effective / exception / insufficient_evidence /
  not_applicable; citations schema-enforced; a pass with no evidence refs is
  invalid output) → deterministic guard that can only downgrade. Same
  LLM-proposes/guard-disposes philosophy as `verdict_guard`.
- **Where the LLM is load-bearing** (and why templates don't compete):
  requirement interpretation at the margins, exception characterization,
  cross-evidence reconciliation, insufficiency detection. Instance-level
  judgment is already paid for by triage verdicts; compliance re-reads it.
- **Three classification levels**: rule-level relevance (versioned crosswalk;
  Wazuh's static tags consumed as join keys and calibration data, not
  trusted), instance-level relevance (deterministic joins: RoPA-lite/asset
  scope, data classes via path rules and asset registry, period membership),
  instance-level judgment (existing verdicts and dispositions).
- **Dual read path (key finding).** The adapter filters at
  `SOCTALK_ADAPTER_MIN_SEVERITY` (default 10) and drops the structured
  syscheck/sca blocks; most compliance-relevant telemetry (level 3-9:
  successful auth, routine FIM, SCA results) never enters the triage stream.
  The evidence engine therefore queries the Wazuh indexer and manager API
  directly at assessment time, over the full corpus, joined to triage
  verdicts by rule_id/agent/timestamp. Streaming path stays lean; retention
  config on the appliance must cover the audit period. Adapter redaction
  discipline (redact_text, redaction_version) extends to evidence extracts,
  with the redaction log in the pack manifest.
- **Home**: batch worker modeled on runs_worker, in `soctalk_enterprise`
  (docstring already reserves "compliance report generators"). Net-new
  concepts: audit-period semantics, evidence provenance objects,
  control/population schema, pack export. No batch/scheduler machinery
  exists today; that is the one real plumbing investment.

## Wazuh mechanics that matter

- Promoted compliance fields (`rule.pci_dss` etc.) are a fixed analysisd set;
  custom frameworks only via `<group>` tags landing in `rule.groups`. New
  regulations never get native dashboard tabs; treat that as a feature (the
  Wazuh dashboard is the SOC surface, soctalk is the compliance surface).
- Rule-level classification at runtime needs only `rule.id`; compliance
  arrays are consumed at pack-authoring time from the pinned ruleset corpus.
- Gap-closing levers, all content: enable cloud/SaaS modules (O365, Azure,
  AWS, GCP, GitHub) for agentless identity/admin events through Wazuh itself;
  agentless SSH + syslog for network gear; FIM whodata for actor attribution;
  audit-readiness baselines per OS (auditd/Windows audit policy) verified by
  custom meta-SCA policies; DB audit trails (pgAudit and friends) forwarded
  as localfile with custom decoders (the personal-data access story for
  GDPR/LGPD); indexer retention sized to audit periods; NTP checks.
  Bundle as an "evidence-ready Wazuh profile" per framework pack.
- Residual non-Wazuh gaps: identity-provider configuration state (MFA
  enforcement, conditional access), covered by the small OAuth supplements.

## GDPR/LGPD specifics

Technical hooks: GDPR Art. 32 / LGPD Arts. 46-49 (security of processing;
Art. 32(1)(d) mandates regular effectiveness testing, a recurring evidence
obligation and the subscription heartbeat), Art. 5(1)(f), Art. 5(2)
accountability. Scope comes from a RoPA-lite mapping (systems → personal-data
categories), not a CDE. Rubrics anchor to proxy standards (CIS/ISO 27002,
what SCA already measures) since the law says "appropriate", not "do X".
Artifacts: quarterly Art. 32 effectiveness report; personal-data incident
register (Art. 33(5) requires documenting ALL breaches including
non-notified, with reasoning); breach-notification dossier generator using
investigation-run timelines as awareness-clock evidence (GDPR 72h, ANPD 3
business days). Channel: DPOs, privacy counsel, DPO-as-a-service shops
(multi-client operators, same shape as MSSP tenancy). Positioning limit:
"Art. 32 evidence and breach-response readiness", never "GDPR compliance".

## Worked example (GDPR, one alert end to end)

Wazuh rule 550 (integrity checksum changed, level 7) fires on
`/data/exports/customers_2026-08.csv` on host db-01, syscheck block carries
whodata actor `svc_etl`. Level 7 means the triage adapter never saw it; the
evidence engine reads it from the indexer. Level 1: crosswalk maps rule 550
to Art. 32(1)(b) via ISO 27002 8.16 / 800-53 SI-7 lineage (Wazuh's own
`gdpr: II_5.1.f` tag corroborates but is not the asserted claim). Level 2:
db-01 is in the RoPA population "customer CRM", the path matches a
personal_data path rule, the period and coverage checks pass, so the
instance counts. Level 3: an Engagement (monthly CRM export window, svc_etl)
matches → authorized/expected → the event becomes operating-evidence in the
Q3 Art. 32 report (one of 3,847 detected-and-dispositioned file events).
Counterfactual actor `jsmith` with vim at 02:14, no engagement → deviation →
register entry plus Art. 33(5) incident record; if escalated, the run
timeline becomes the 72-hour awareness evidence. Without whodata the two
branches are indistinguishable, which is why the audit baseline is a pack
prerequisite verified by SCA.

## Risks

- Kill shot: the channel does not accept the deliverable as audit-useful.
- Wazuh Inc. closing the content gap natively (their pattern to date is
  capability marketing, not maintained framework content; erosion is slow).
- Over-mapping (thematic tagging inflating coverage) damaging the brand;
  the refutation pass and honest denominators exist to prevent it.
- Consulting-in-disguise economics on the one-off engagement if scope is not
  controlled.

## Next steps (both cheap, run in parallel, independent outcomes)

1. **QSA falsification test.** Hand-build evidence packs for 3 PCI controls
   (log review 10.4, FIM 11.5.2, SCA baseline 2.2) from real Wazuh data in
   the verify environment: extracts, population statement, coverage stats,
   exceptions, hashes, signoff. Show to ~3 QSAs and ~2 vCISO/MSP operators.
   Questions: accept it? what would you still request? reduce billable
   effort? resell it? at what fixed price? No pull afterward: park the
   evidence tier.
2. **Pack demand test.** Canonical mapping schema + first-cut NIS2 Art. 21.2
   mapping for one or two measures, independently reviewed, published free. Measure
   downloads and inbound. Packs failing while QSAs accept (or vice versa)
   redirects rather than kills the direction.
