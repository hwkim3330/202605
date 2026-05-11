## Summary

<!-- 1–3 bullets on what changes and *why*. -->

## Changes

- [ ] Code change (server / agent / UI)
- [ ] Docs (README / methodology / API / samples)
- [ ] Test (unit / property / sample report)
- [ ] CI / repo

## Verification

<!-- How you tested. Paste the actual commands + outputs that make this PR
trustworthy. The samples folder is full of examples of the kind of evidence
that's persuasive here. -->

```
# example
python3 -m unittest tools.test_packet_agent -v
curl -sS -X POST http://localhost:8080/api/wire-validation … | python3 -c '…'
```

## Checklist

- [ ] `node --check server.js && node --check public/app.js`
- [ ] `python3 -m unittest tools.test_packet_agent`
- [ ] Updated `CHANGELOG.md`
- [ ] Updated `docs/methodology.md` if the change affects what a number means
- [ ] Sample report regenerated if user-facing output changed (`cp reports/*.html docs/samples/...`)
