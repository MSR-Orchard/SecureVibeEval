# Bundled mini-swe-agent

SafeBench includes its own mini-swe-agent source snapshot at `mini-swe-agent/`.
Evaluation setup uses this local copy, so a SafeVibe checkout is not required.
The snapshot is copied unchanged from the SafeVibe release bundle and verified
against its existing file manifest.

From this directory, verify it with:

```bash
shasum -a 256 -c mini-swe-agent.SHA256SUMS
```

The upstream license is preserved at
[mini-swe-agent/LICENSE.md](mini-swe-agent/LICENSE.md).
