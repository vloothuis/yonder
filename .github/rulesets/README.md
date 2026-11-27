# Rulesets

`main.json` protects the default branch. Changes land only through a
squash-merged pull request with passing checks. No approval is required.
Apply a change with:

```bash
gh api -X PUT repos/vloothuis/yonder/rulesets/28227387 --input .github/rulesets/main.json
```
