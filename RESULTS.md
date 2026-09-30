# Reporting results

How to put an implementation's results on the record. The form is a small JSON file
submitted by pull request; the directory is the record. Reports are versioned,
attributable to their commit author, and reviewable like any other change.

## Where

One file per report, under the release the run was made against:

```
results/<release>/<implementation>-<YYYY-MM-DD>.json
```

Example: `results/draft-02.0/authority-graph-2026-09-29.json`.

A new run of the same implementation is a new file, not an edit. History is the point.

## Form

```json
{
  "release": "draft-02.0",
  "implementation": {
    "name": "authority-graph",
    "url": "https://github.com/example/authority-graph",
    "version": "commit or tag the run was made at",
    "language": "TypeScript"
  },
  "harness": "external",
  "harness_ref": "link to the harness or adapter used, if not runner/run_vectors.py",
  "evidence_rung": "author-operated",
  "operator": "name of who ran it",
  "date": "2026-09-29",
  "suites": {
    "vectors.json": {
      "dispositions": {
        "approval_key_accept_enrolled_approver": "pass",
        "approval_key_reject_different_action": "pass",
        "token_multihop_accept": "not-run"
      }
    },
    "jcs_vectors.json": { "dispositions": {} },
    "a2a_vectors.json": { "dispositions": {} }
  },
  "artifacts": [
    "links to PRs, CI runs, or commits that substantiate the run"
  ],
  "notes": "anything a reader needs to interpret the dispositions"
}
```

Rules, all of them load-bearing:

- `release` MUST name a release in this repository, and the run MUST have been made
  against bytes matching that release's `SHA256SUMS`. A report against modified vector
  files is a report about different vectors.
- Every case in a listed suite gets a disposition: `pass`, `fail`, or `not-run`.
  Partial runs are welcome and normal; `not-run` is a first-class answer, and a suite
  you did not take is omitted entirely rather than zero-filled. Nothing here folds
  into a score.
- `evidence_rung` is `author-operated` (the implementation's own people ran it) or
  `independently-reproduced` (someone else ran it against the named version and got
  the same dispositions). State which; both are useful, they are not the same thing.
- `harness` is `repo-runner` if the run used `runner/run_vectors.py` with an adapter,
  else `external` with `harness_ref` pointing at what was used. External harnesses
  are fine; the reference runner exists so that two reports are comparable, so say
  when yours is not.
- `fail` dispositions are welcome. A disagreement with the reference implementation
  is exactly what these vectors exist to surface, and a report that includes its
  failures is worth more than one that waited until it had none.

## What merging means

A merged report is recorded, not endorsed. The maintainer checks the form (schema,
release pin, rung stated), not the truth of the dispositions. Independent
reproduction is what upgrades a report, and it arrives as its own file with
`evidence_rung: independently-reproduced` and its own operator.

## Relationship to the requirements draft

Same boundary as everywhere else in this repository: these are agreement vectors.
A report, whatever its dispositions, states agreement or disagreement with the
reference implementation at a pinned release. It is not a conformance claim against
draft-reece-wimse-cross-org-delegation, and reports should not describe themselves
as one.
