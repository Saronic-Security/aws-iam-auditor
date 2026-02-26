# AWS IAM Hygiene Auditor

A Claude Code-driven AWS IAM security auditor that scans any AWS account for IAM hygiene issues, analyzes findings with AI judgment and real-world threat intelligence, and creates Linear tickets for remediation tracking.

## How It Works

```
You → "audit my AWS account" → Claude Code runs scanner → analyzes findings
    → validates for false positives → presents report → you approve
    → Linear tickets created with remediation steps
```

The human only shows up at the end to approve.

## Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/Saronic-Security/aws-iam-auditor.git
cd aws-iam-auditor
```

### 2. Install dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Have an AWS CLI profile configured
```bash
# SSO (recommended)
aws configure sso --profile <your-profile>

# Or static credentials
aws configure --profile <your-profile>
```

You only need **read-only IAM access**:
- `iam:GenerateCredentialReport`
- `iam:GetCredentialReport`
- `iam:GetAccountPasswordPolicy`
- `iam:ListUsers`
- `iam:ListUserPolicies`
- `iam:ListAttachedUserPolicies`
- `iam:ListRoles`
- `sts:GetCallerIdentity`

### 4. Run the audit
Open Claude Code in this directory and say:
```
Audit IAM hygiene for profile <your-profile-name>
```

That's it. Claude handles everything:
- SSO login if your session is expired (browser pops up automatically)
- GovCloud detection and warning if applicable
- Fetches latest threat intelligence
- Scans all IAM users, roles, and policies (read-only)
- Analyzes findings with severity, CIS benchmarks, and MITRE ATT&CK context
- Validates for false positives before showing you anything
- Presents a clean report grouped by severity
- Creates Linear tickets after you approve

### You don't need to:
- Know Python or boto3
- Understand CIS benchmarks (the tool explains everything)
- Write remediation steps (generated with real-world context)
- Have any special permissions beyond read-only IAM access

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

Every finding is enriched with:
- CIS AWS Foundations Benchmark reference
- MITRE ATT&CK technique IDs
- Real-world breach context (Capital One, Uber, Scattered Spider, etc.)
- Privilege escalation / data leakage / lateral movement flags

## GovCloud Support

If your profile points to a GovCloud region (`us-gov-west-1` or `us-gov-east-1`), the scanner will:
- Display a warning banner (with cats)
- Escalate all severities by one level (MEDIUM → HIGH, HIGH → CRITICAL)
- Add NIST 800-171 and CMMC references alongside CIS benchmarks
- Flag findings that could affect FedRAMP authorization boundary

## Scanner CLI

You can also run the scanner standalone without Claude Code:

```bash
# Basic scan
source .venv/bin/activate
python scanner.py --profile <name>

# Save to file
python scanner.py --profile <name> --output findings.json

# Fetch latest threat intel before scanning
python scanner.py --profile <name> --update-intel --output findings.json
```

## Architecture

```
┌─────────────────────┐
│   scanner.py        │  boto3, read-only IAM API calls → JSON findings
└────────┬────────────┘
         │
┌────────▼────────────┐
│   risk_intel.json   │  CIS, MITRE ATT&CK, breach context per check
└────────┬────────────┘
         │
┌────────▼────────────┐
│   Claude Code       │  AI analysis, adversarial validation, reporting
│   (via CLAUDE.md)   │  Linear ticket creation after human approval
└─────────────────────┘
```

- **scanner.py**: Pure Python/boto3 data collector. Read-only. Outputs JSON.
- **risk_intel.json**: Threat intelligence database — CIS controls, MITRE mappings, real breach references.
- **CLAUDE.md**: Workflow instructions for Claude Code — analysis, validation, reporting, ticket creation.
- **Claude Code**: The AI layer that interprets findings, generates remediation, and creates tickets.

Built for the Claude Hackathon (Feb 2026).
