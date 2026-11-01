# Evaluation Report

## Full-dataset structural checks

The root `output.csv` was checked against the 518 request rows in `dataset/deletion_requests.csv`.

| Check | Result |
| --- | ---: |
| Output rows | 518 / 518 |
| Request case IDs covered | 518 / 518 |
| Required header and field count | Pass |
| Valid status values | 518 / 518 |
| `steps_json` parses as an array | 518 / 518 |
| Step numbers are consecutive from 1 | 518 / 518 |
| `NOT_APPLICABLE` rows contain `[]` | Pass |
| Numeric case ordering | Pass |

The hidden canonical answers for the 518 full-dataset cases are not available in the workspace. Therefore, case-level status accuracy, semantic field accuracy, exact row accuracy, and canonical sequence accuracy are **not measured**; structural validation is not a substitute for comparison with hidden answers. The supplied 32 sample cases use `case_01`–`case_32` and are separate from the full request set, which starts at `case_33`.

## Additional evaluation cases

These are supplemental scenarios and expected behaviors; they are test-case specifications, not claims of hidden-gold evaluation:

1. **No deletion authorization** — No request evidence authorizes deletion. Expected: `NOT_APPLICABLE` and an empty steps array.
2. **Policy-permitted tombstone** — Direct identifiers are removed while a stable internal reference remains in a record that policy requires retaining. Expected: do not report the permitted reference as prohibited PII; verify the retained record and required redaction.
3. **Data recreated through a replica or restore** — A copy reappears after deletion or an active process can restore it. Expected: report the remaining record and active risk, then order remediation before future verification.

## Failures found and improvements

- A prior export-order issue was recorded in the session log and fixed by sorting cases numerically before writing.
- Packaging inspection found that the first archive omitted the top-level prompt and configuration/dependency files; the archive was rebuilt to include them.
- The previous usage report contained unsupported token and model-call figures. It was corrected to report the application's actual zero-LLM usage rather than inferred figures.

