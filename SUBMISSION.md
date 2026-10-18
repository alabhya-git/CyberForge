# TwoKey — CyberForge submission notes

## Title and one-sentence pitch

**TwoKey: Evidence-Authorized Incident Response That Preserves Critical Business Workflows**

TwoKey requires an automated containment plan to pass two machine checks: an evidence-to-action authorization rule and an executable attack/business replay, both bound to the exact policy the gateway applies.

## Live demonstration

Open `http://127.0.0.1:8100` while the local stack is running.

1. **S1:** a reports credential exports synthetic customer rows while client-controlled text asks the investigator to disable payments. Key 1 rejects that unrelated target in the manual fault-injection check. The planned credential/resource restriction passes a shadow replay and is applied by the protected gateway. Checkout remains operational.
2. **S2:** a path-only plan initially misses an alternate export route. The first shadow replay shows the actual leaked canary as a counterexample. A resource-level plan is selected and passes the second replay.
3. **S3:** preserving an export using the same compromised credential conflicts with blocking that identical request. The planner escalates without applying a policy.
4. **Business impact:** after S1, the operator replays the broadest authorized responses in the isolated shadow lab. Each one still stops the 12 attack probes, but isolating the shared storefront passes 0/40 business assertions (about ₹34,000/h at the default illustrative assumptions). TwoKey's plan passes 40/40 at ₹0/h. These comparison plans are never applied.
5. **Judge control:** the judge marks the reports-key export as required on the contained incident. The solver returns a minimal conflict ("Block the alias export path" vs "Keep the reports-key export working"). The live quarantine stays in place, with credential rotation as the recommended remediation.

The manual Key 1 check is labeled fault injection. It is not evidence that an AI model followed an injected instruction. The local default model mode is disabled; a live Anthropic model and a separate 120-system-trial comparison are available only after supplying a valid provider key and model identifier.

## Reproducible measured result

The frozen 50-variant **deterministic architecture evaluation** completed on the current protected-path source fingerprint `958a8130e58ce156f0c93e3ce50838124853601c27f3d0088a42b85a2009ffe0`, which includes the business-requirements continuation. The earlier build `b404d820…` produced the same 50/50 result, and its rows remain in the JSONL.

- 50/50 runs reached useful safe completion.
- 0/50 manually checked unrelated payments actions were authorized.
- In each passing run, 12/12 synthetic attack probes were contained and 40/40 business assertions passed in shadow replay.
- No run errors in that 50-run result set; median end-to-end wall time was 7.426 seconds (7.714 seconds on the earlier build).
- **0 live model trials** were performed. These figures measure the enforcement architecture against synthetic User-Agent variants. They do not estimate real-world injection resistance or insurer losses.

Raw rows and exact manifest/source hashes are in `artifacts/architecture-benchmark.jsonl` and `artifacts/architecture-benchmark-summary.json`. Earlier development runs are separately labeled `artifacts/preliminary-architecture-runs.jsonl` and excluded from the stated final-build result.

## Demo and evidence files

- `artifacts/twokey-demo.webm` — actual local UI walkthrough of S1, measured broader responses, a requirement conflict and S2; model-disabled label remains visible.
- `artifacts/twokey-contained.png`, `artifacts/twokey-impact.png`, `artifacts/twokey-conflict.png` and `artifacts/twokey-replan.png` — still frames.
- Downloadable JSON run bundles in the UI; `scripts/verify_bundle.py` checks evidence, approvals, replay and applied-plan binding.
- `scripts/smoke.py` — end-to-end S1/S2/S3 and security-boundary checks.
- `README.md` — startup, test, deployment, threat boundary and limitations.

## Technical contribution and scope

The original contribution demonstrated here is the integration of field provenance, semantic target authorization, constrained planning, executable business-impact replay, counterexample refinement and a receipt-bound policy executor. The model proposes and explains when configured; it never receives a policy-mutation tool. The deterministic catalog also supplies candidates if the model is unavailable or produces an invalid proposal.

This is a synthetic local prototype. It does not use a real SOC vendor, EDR, payment provider, customer dataset or production network. Replay verifies only the named requests, assertions, snapshot and service build. The code assumes an intact host, gateway, verifier, detector and operator policy. The normal narrow quarantine cannot be undone automatically without reopening the incident; the UI refuses that unsafe undo.

## Disclosure

The code, interface, documentation and evaluation harness were produced with Codex assistance in this workspace, and continued with Claude Code assistance (business requirements, rupee estimates, conflict explanation, measured alternative replays, model-adapter fix, additional tests and UI). Runtime dependencies are pinned in `requirements.txt` and `web/package-lock.json`; their respective licenses should be checked before final distribution. Inspiration for the evidence/control boundary includes the [CaMeL research paper](https://arxiv.org/abs/2503.18813). TwoKey does not reproduce CaMeL or inherit its formal guarantees.
