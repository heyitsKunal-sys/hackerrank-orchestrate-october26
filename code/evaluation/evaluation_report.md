# Evaluation Report

## Public sample results

The agent was evaluated against all 32 participant-provided rows in `dataset/sample_output.csv`.

| Metric | Result |
|---|---:|
| Case-level deletion-status accuracy | 28 / 32 (87.50%) |
| Exact step-sequence accuracy | 7 / 32 (21.88%) |
| Expected steps | 193 |
| Predicted steps | 155 |
| Step precision | 60.65% |
| Step recall | 48.70% |
| Step F1 | 54.02% |
| Aligned per-field accuracy | 61.20% |

Field accuracy was measured by step position, with missing or extra positions counted as incorrect for every field:

| Field | Accuracy |
|---|---:|
| `step_no` | 76.65% |
| `phase` | 70.56% |
| `system_id` | 50.76% |
| `resource_id` | 49.24% |
| `operation` | 52.28% |
| `state` | 54.82% |
| `evidence_id` | 74.11% |

These figures measure only the public sample set. They are not a claim of hidden-set accuracy.

The final 518-case `output.csv` was regenerated with Tesseract OCR 5.4.0 available. The public-sample metrics and all seven additional checks were unchanged.

## Additional evaluation cases

The evaluation runner applies seven extra deterministic checks:

1. Spanish explicit account deletion is authorized.
2. French explicit account deletion is authorized.
3. A marketing-only unsubscribe that explicitly keeps the account is not a deletion request.
4. A data-access/export request that keeps the account is not a deletion request.
5. An email-correction request that continues service is not a deletion request.
6. Evidence captured after `audit_at` is excluded from the case.
7. Finding, remediation, and verification steps are phase-ordered and consecutively numbered.

All seven checks pass.

## Failures found and improvements made

- Four sample statuses still disagree. Three cases lack a directly attributable account/analytics resource in the machine-readable evidence available to this implementation; one public sample has no recognizable deletion instruction in its request text. The agent deliberately does not manufacture resource IDs or authorization from a workflow-status claim.
- Exact sequence accuracy remains low because some sample answers associate anonymous analytics or account-absence observations with a user without an explicit identity link in the extracted artifact. More complete cross-artifact identity linking is needed before claiming those resources.
- The first implementation missed quoted lookup values, lost lookup context when a trace split across start/completion log lines, and did not recognize ASCII85-wrapped PDF streams. These were corrected; log trace context is now merged, PDF text is extracted with the standard library, and case evidence is filtered by both capture availability and observation time.
- Support contact lookups and analytics contact lookups are treated as deletable secondary identifiers; direct identifiers detected in support messages trigger redaction. Active connector and restorable backup states receive separate remediation and verification steps.
- PNG OCR is supported when Tesseract is installed. Without it, the agent emits an explicit warning rather than pretending those screenshots were inspected.

Run `python code/evaluation/main.py` to reproduce the public-sample metrics and custom checks. The evaluator reads public examples only; it does not use labels to generate predictions.
