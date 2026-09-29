# Checks

Every check reads its settings from the policy (`attestor.yaml` or a pack). All checks accept `enabled`, `severity` (`block`, `warn`, `info`) and `regulatory_refs`.

## citation_grounding

For each sentence with at least one valid citation, attestor scores it against each cited source and keeps the best score. The score is the highest of:

- content-word recall: share of the sentence's non-stopword tokens found in the source
- 3-gram overlap on content words
- longest shared character span, as a share of the sentence length

Before scoring, every figure in the sentence must appear in at least one cited source. Figures are normalised to a value and a unit: currency, `%` (also "percent"), `x` multiples and `bps`, with scale words applied (`$4.2 million` is 4,200,000). A bare number in the source can support a currency amount in the sentence. Period labels (`FY2025`, `CY24`, `Q3`, `H1 2025`) are compared as labels, and a source that says `FY2024` also supports a sentence that says `2024`. Ordinals like `3rd` are ignored.

| Option | Default | Meaning |
|---|---|---|
| `support_threshold` | 0.6 | At or above: supported |
| `reject_threshold` | 0.3 | At or below: unsupported |

Scores in between are uncertain. Without a judge they are reported as warnings. With `--judge claude` (or `judge.provider: anthropic` in the policy) the judge decides, and a judge failure is reported as a warning rather than a pass. Failed calls are listed in the report's `judge_calls` with the error.

## citation_coverage

Flags factual sentences with no citation. A sentence counts as factual if it contains a digit or performance language (revenue, grew, margin, outperformed, largest, and similar) and has at least three content words. Questions are skipped.

| Option | Default | Meaning |
|---|---|---|
| `min_coverage` | 1.0 | Share of factual sentences that must be cited |

## phantom_citation

Flags any citation marker whose id is not in `sources`.

## pii_leak

Regex detectors, with validation where a checksum exists:

| Detector | Notes |
|---|---|
| `ssn` | US format, excludes invalid area and group numbers |
| `credit_card` | 13 to 19 digits, must pass the Luhn check |
| `iban` | Must pass the mod-97 check |
| `us_bank_account` | Only when preceded by "account", "acct", "routing" or "ABA" |
| `email` | |
| `phone` | North American formats with `-`, `.` or `(area code)` separators |

Choose detectors with `detectors: [ssn, email]`. Values are masked in findings, so reports and logs never contain the raw data.

## required_disclosures

`phrases` is a list of plain strings (matched literally, case-insensitive) or mappings with `label` and a regex `pattern`.

## prohibited_language

`terms` and `extra_terms` are regexes matched on word boundaries. A match is skipped only when a negation (no, not, never, cannot, without, and similar) is within the three words before it and in the same clause. "No investment is risk-free" is not flagged. "No fees and guaranteed returns" is.

## Audit log

Each `attestor check` run appends one JSON line per case. Records hold the case and policy hashes, pack, verdict, finding counts, failed check ids, the number of judge calls and `prev_hash`. `hash` is SHA-256 over the canonical JSON of the record without `hash`. `attestor verify-log` recomputes the chain and reports the first bad record.
