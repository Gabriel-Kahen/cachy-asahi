# Repository database header correction

Corrects the NativeCI blocker on3014: duplicate fields silently overwrote earlier values, while strip('%') admitted %%PGPSIG%% aliases. That sealed candidate and its captures remain unchanged.

Recognized headers retain the original startswith/endswith-percent boundary. They now require exact `%[A-Z0-9_]+%`, use exact delimiter slicing and reject every duplicate key before initialization. Ordinary `% savings` and `%PGPSIG` values without a closing delimiter remain values. All signature/capability/first-error/stable gates stay held; client stage changes onlytwo hash pins.

Actual targeted release30 and full release87/client109 pass without skips. New controls include13 re-signed DB refusals, two re-signed ordinary-value positives and12 independent inert old/new countermodels. Each real DB variant first passes database/manifest/package cryptographic verification. No native or hosted successor outcome is claimed.

Evidence and complete copy map: `artifacts/reviews/repo-add-database-field-correction-20261014/`. Verify with `python -B artifacts/reviews/repo-add-database-field-correction-20261014/verify.py`. Fresh independent NativeCI review is required before Root commit/publication.
