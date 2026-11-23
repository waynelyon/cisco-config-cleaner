# Repository audit — 2026-11-23

What this repo does: a native, offline macOS app for cleaning Cisco configuration batches. Assumed load: one engineer importing multiple real configuration files, up to the advertised per-file limit. Reviewed all tracked source, tests, scripts, documentation, fixtures, plist and asset inventory, plus the ignored legacy source backup. Images are design sources, not dead code. Ranking combines likely exposure with consequence, not just security severity.

## Ranked findings and fix plan

Each numbered finding has a separate fix commit. Regression tests are added with the relevant fix rather than counting each absent test as another issue.

| Rank | Likelihood | Problem / concrete trigger | Fix / consequence if left alone |
|---|---|---|---|
| 01 | High | `username password secret 9 DEMO_HASH` leaves the hash exposed. | Protect username values while matching credential commands; otherwise shared exports leak secrets. |
| 02 | High | `password strengthSecret` matches the password-policy exemption. | Require complete control-command tokens; otherwise ordinary passwords survive. |
| 03 | High | An escaped quote in a quoted password leaves the suffix visible. | Consume escaped quotes and conservatively redact unterminated quoted values. |
| 04 | Medium | A truncated PEM/certificate block has no closing marker and is left intact. | Redact to the block terminator or EOF; otherwise pasted fragments expose key material. |
| 05 | Medium | A CR-only file beginning with a comment skips all credential processing. | Normalize CR-only command boundaries and preserve its line-ending convention. |
| 06 | High | `snmp-server community password RO` also redacts `RO`. | Parse community syntax before generic keywords; otherwise valid configuration options are lost. |
| 07 | Medium | `key\tchain KEYS` is changed into `key [REDACTED] KEYS`. | Make nonsecret command recognition whitespace-tolerant and context-aware. |
| 08 | Medium | A contiguous high-bit ACL wildcard such as `255.0.0.0` is treated as a subnet mask. | Carry wildcard/subnet meaning into mapping constraints; otherwise host/network relationships change. |
| 09 | High | Label mode treats `12:34:56` as IPv6 and splits IPv4-mapped IPv6 addresses. | Use validated whole address tokens and canonical aliases. |
| 10 | Medium | A discovered serial equal to a command word is substituted throughout configuration grammar. | Restrict serial replacement to explicit fields and free-text metadata; otherwise commands are corrupted. |
| 11 | High | Copying preview text includes display line numbers and diff markers. | Remove display-only prefixes from clipboard selections; otherwise pasted configurations contain junk. |
| 12 | Medium | Reimporting a clean file doubles leading IP markers and remaps already anonymized addresses. | Treat marked addresses as already cleaned. |
| 13 | Medium | A UTF-8 BOM before `hostname` prevents hostname recognition. | Strip the BOM at the cleaning boundary while preserving option-off input. |
| 14 | Medium | `hostname edge` and `ntp server EDGE` get inconsistent anonymization. | Match hostname identity case-insensitively. |
| 15 | High for batches | Every protected hostname token triggers another whole-file replacement scan. | Protect/restore values per line; otherwise many neighbor lines cause quadratic work. |
| 16 | High for batches | Regular expressions are compiled repeatedly for every configuration line. | Reuse compiled expressions; otherwise larger files spend needless time compiling identical patterns. |
| 17 | Medium | Import checks the file size before an unbounded read; a growing file can exceed the limit. | Bound the actual read and validate bytes received. |
| 18 | Medium | Unlimited 20 MB imports can exhaust memory. | Enforce a total input budget and queue bound with visible errors. |
| 19 | High for batches | Cleaning runs on the UI thread; Reset also triggers several full recomputations. | Schedule bounded background work, discard stale results and block stale exports. |
| 20 | Medium | The supposedly bounded preview first splits both complete files into line arrays. | Bound text before splitting/diffing; otherwise large files waste memory for invisible lines. |
| 21 | Medium | Real export collision, partial failure and original-preservation paths have no automated test. | Extract the folder export operation and test actual filesystem behavior. |
| 22 | Medium | Local builds inherit the host deployment target instead of the release's macOS 14 target. | Share the minimum OS contract in builds and bundle metadata. |
| 23 | Medium | Bundle and compiled version strings can drift without a build failure. | Compare an executable version output to the plist during builds. |
| 24 | Medium over time | No automated checks run on future pushes or pull requests. | Add macOS build/self-test CI, preventing regression commits from silently passing review. |

## Dead files and deliberate limits

No tracked dead implementation file was found. `main-v1.swift` is an ignored, inactive local backup, absent from both build lists and Git; it is not shipped. The source PNG and iconset are retained to regenerate the app icon. App bundles and release archives are ignored build outputs, not source duplicates to delete.

Logical IP mapping deliberately exposes topology and is reversible. Markers do not prevent all pasted commands from running. Unknown Cisco grammar and unsupported hostname references still require review. Signing/notarization, live-device syntax validation, Intel execution and macOS 14 runtime behavior are not established by a source audit or cross-compilation.

## Completion

All 24 ranked findings were addressed, with one primary commit per finding and regression coverage for the behavioral changes. Review corrections are folded into their owning commits. Every fix passed the native build and existing self-tests. New tests cover secret edge cases, retained commands, address semantics, clipboard selection, bounded inputs, asynchronous freshness, and actual export collisions/partial failures.

The active source is now version 27.0.1 (build 8). The previously published 27.0.0 binary remains a separate artifact until a new release is explicitly published. GitHub automation runs native and universal builds on future pushes and pull requests.

This is a bounded audit, not proof that every possible defect has been found. Fewer than 50 concrete, independently actionable findings were established; no issues were invented to fill the quota.
