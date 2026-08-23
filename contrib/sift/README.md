# git-sift — evidence-based PR triage, built into git itself

`git sift` screens a branch like a maintainer screens a pull request and
prints a transparent scorecard backed by quoted evidence.  Diagnostic only:
it never touches code, never closes anything — the verdict stays human.

## Build

The shared library is built automatically as part of `make all`.
Manual build:

    cc -shared -fPIC -o contrib/sift/libnetspy.so contrib/sift/libnetspy.c -ldl

## Usage

    # maintainer mode: triage a branch ("the PR") against its base
    git sift feature-branch

    # explicit base
    git sift main..feature-branch

    # contributor mode: scan uncommitted changes before pushing
    git sift

    # Layer 2 — run the tests inside the network-guarded sandbox
    git sift feature --exec "python3 -m pytest -q"

    # offline Layer 3 replay for demos and precomputed reviews
    git sift feature --llm-response review.txt

    # optional live OpenRouter review; key comes only from OPENROUTER_API_KEY
    git sift feature --llm --llm-model provider/model

    # CI gating (maintainer's choice; score below threshold exits 1)
    git sift feature --fail-below 40

## What it checks

Layer 0 (mechanical) and Layer 1 (heuristic) are deterministic, zero-LLM:

- placeholder tests (`assert True`, `expect(true).toBe(true)`, skipped/empty bodies)
- TODO/FIXME floods (5+ new markers)
- comment/code imbalance (>=45% of added lines are comments)
- leaked assistant voice ("Here's the implementation…")
- commit velocity (5 commits in <120s) and machine-speed diffs
- commit bombs (single commit +500 lines)
- repeated / low-information commit subjects
- description vs diff size mismatch
- no tests for 50+ lines of new logic

Layer 2 (sandboxed execution) runs your test command with an LD_PRELOAD
network guard (`libnetspy.so`) that blocks and records every outbound
connection and DNS lookup.  A test suite that phones home during its own
run is evidence on the scorecard — the one thing a slop author cannot fake.

Layer 3 is optional and evidence-constrained. It checks intent mismatch, test
adequacy, and likely reinvention. Every accepted model finding must quote an
exact substring from the submitted context with confidence of at least 80;
each costs only 3 points and the layer is capped at 9. `--llm-response` applies
the same validation without making a network request.

## Score

100 minus 18/HIGH, 8/MED, 3/LOW.  Exit code 1 when below `--fail-below`
(default 40) — wire that into CI only if *you* want a gate; sift itself
never gates.
