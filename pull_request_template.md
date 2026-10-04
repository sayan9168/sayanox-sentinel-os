ls .github .github/workflows
cd /workspace && ls .github/workflows/ && mkdir -p .github/ISSUE_TEMPLATE && cat > .github/ISSUE_TEMPLATE/bug_report.md << 'EOF'
---
name: " Bug Report
about: Report a problem with Sayanox Sentinel OS
title: "[BUG] "
labels: bug
---

## Describe the bug
A clear and concise description of what the bug is.

## To Reproduce
Steps to reproduce the behavior.

## Expected behavior
What you expected to happen.

## Environment
- OS: [e.g. Ubuntu 24.04]
- Python version: [e.g. 3.12]
- Node version: [e.g. 20.x]
- Deployment: [Docker / Local]

## Logs / Screenshots
If applicable, add logs or screenshots.
EOF
cat > .github/ISSUE_TEMPLATE/feature_request.md << 'EOF'
---
name: "✨ Feature Request
about: Suggest an idea for Sayanox Sentinel OS
title: "[FEATURE] "
labels: enhancement
---

## Problem statement
What problem does this feature solve?

## Proposed solution
Describe the solution you'd like.

## Alternatives considered
Any alternative solutions or features you've considered.
EOF
cat > .github/PULL_REQUEST_TEMPLATE.md << 'EOF'
## Description
What does this PR do?

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Security patch
- [ ] Refactor / CI-CD

## Checklist
- [ ] Backend tests pass (`pytest`)
- [ ] Frontend builds cleanly (`npm run build`)
- [ ] No new lint errors
- [ ] Documentation updated (README if needed)
EOF
ls -la .github .github/workflows .github/ISSUE_TEMPLATE
