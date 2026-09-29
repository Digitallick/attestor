# Checks

Every check reads its settings from the policy (`attestor.yaml` or a pack). All checks accept `enabled`, `severity` (`block`, `warn`, `info`) and `regulatory_refs`.

## citation_grounding

For each sentence with at least one valid citation, attestor scores it against each cited source and keeps the best score. The score is the highest of:

- content-word recall: share of the sentence's non-stopword tokens found in the source
- 3-gram overlap on content words
- longest shared character span, as a share of the sentence length

Before scoring, any figure in the sentence must appear in at least one cited source. Figures are compared after removing thousands separators and trailing zeros, so `$1,200.50` matches `1200.5`. Labels like `FY2025` and `Q3` are not treated as figures.

| Option | Default | Meaning |
|---|---|---|
| `support_threshold` | 0.6 | At or above: supported |
| `reject_threshold` | 0.3 | At or below: unsupported |

Scores in between are uncertain. Without a judge they are reported as warnings. With `--judge claude` (or `judge.provider: anthropic` in the policy) the judge decides, and a judge failure is reported as a warning rather than a pass.

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
| `phone` | North American formats |

Choose detectors with `detectors: [ssn, email]`. Values are masked in findings, so reports and logs never contain the raw data.

## required_disclosures

`phrases` is a list of plain strings (matched literally, case-insensitive) or mappings with `label` and a regex `pattern`.

## prohibited_language

`terms` and `extra_terms` are regexes matched on word boundaries. A match is skipped when a negation (no, not, never, cannot, without, and similar) appears shortly before it in the same sentence, so "no investment is risk-free" is not flagged.

## Audit log

Each `attestor check` run appends one JSON line per case. Records hold the case and policy hashes, pack, verdict, finding counts, failed check ids, the number of judge calls and `prev_hash`. `hash` is SHA-256 over the canonical JSON of the record without `hash`. `attestor verify-log` recomputes the chain and reports the first bad record.
