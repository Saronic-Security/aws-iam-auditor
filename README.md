# AWS IAM Hygiene Auditor

A Claude Code-driven AWS IAM security auditor that scans an AWS account for IAM hygiene issues, analyzes findings with AI judgment, and creates Linear tickets for remediation tracking.

## How It Works

```
You → "audit my AWS account" → Claude Code runs scanner → analyzes findings
    → validates for false positives → presents report → you approve
    → Linear tickets created with remediation steps
```

The human only shows up at the end to approve.

## Setup

```bash
pip install -r requirements.txt
```

Ensure you have an AWS CLI profile configured with read-only IAM access:
```bash
aws configure --profile <your-profile>
# or use AWS SSO
aws sso login --profile <your-profile>
```

Required IAM permissions (read-only):
- `iam:GenerateCredentialReport`
- `iam:GetCredentialReport`
- `iam:GetAccountPasswordPolicy`
- `iam:ListUsers`
- `iam:ListUserPolicies`
- `iam:ListAttachedUserPolicies`
- `iam:ListRoles`
- `sts:GetCallerIdentity`

## Usage

Open Claude Code in this directory and say:

```
Audit IAM hygiene for profile <your-profile-name>
```

Claude will:
1. Run the scanner (all read-only API calls)
2. Analyze findings and assign severity
3. Validate findings for false positives
4. Present a report grouped by severity
5. Create Linear tickets after your approval

## Checks

| # | Check | Severity | Source |
|---|-------|----------|--------|
| 1 | Root account with active access keys | CRITICAL | Credential Report |
| 2 | Root account without MFA | CRITICAL | Credential Report |
| 3 | Users without MFA | HIGH | Credential Report |
| 4 | Access keys >90 days old | HIGH | Credential Report |
| 5 | Active but never-used access keys | MEDIUM | Credential Report |
| 6 | Console access, no login >90 days | MEDIUM | Credential Report |
| 7 | Password not changed >90 days | LOW | Credential Report |
| 8 | Directly attached user policies | MEDIUM | IAM API |
| 9 | Inline policies on users | MEDIUM | IAM API |
| 10 | Overprivileged users (Admin/PowerUser) | HIGH | IAM API |
| 11 | Unused IAM roles (>90 days) | MEDIUM | IAM API |
| 12 | Password policy non-compliance | HIGH | IAM API |

## Architecture

- **scanner.py**: Pure Python/boto3 data collector. Read-only. Outputs JSON.
- **CLAUDE.md**: Workflow instructions for Claude Code — analysis, validation, reporting, ticket creation.
- **Claude Code**: The AI layer that interprets findings, generates remediation, and creates tickets.

Built for the Claude Hackathon (Feb 2026).
