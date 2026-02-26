#!/usr/bin/env python3
"""AWS IAM Hygiene Scanner — Read-only IAM security checks.

Scans an AWS account via a CLI profile and outputs JSON findings.
All operations are read-only (list/get/generate-credential-report).

Usage:
    python scanner.py --profile <aws-profile-name>
    python scanner.py --profile <aws-profile-name> --output findings.json
"""

import argparse
import base64
import csv
import io
import json
import sys
import time
from datetime import datetime, timezone
from typing import Any

import subprocess

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound, UnauthorizedSSOTokenError


# --- Constants ---
STALE_DAYS = 90
GOVCLOUD_REGIONS = {"us-gov-west-1", "us-gov-east-1"}
OVERPRIVILEGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}
CIS_MIN_PASSWORD_LENGTH = 14


def days_since(date_str: str) -> int | None:
    """Return days since a date string, or None if not applicable."""
    if not date_str or date_str in ("N/A", "not_supported", "no_information"):
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


def finding(check: str, severity: str, resource: str, detail: str, data: dict | None = None) -> dict:
    """Create a standardized finding dict."""
    return {
        "check": check,
        "severity": severity,
        "resource": resource,
        "detail": detail,
        "data": data or {},
    }


class IAMScanner:
    def __init__(self, profile: str):
        self.profile = profile
        try:
            self.session = boto3.Session(profile_name=profile)
        except ProfileNotFound:
            print(f"\nERROR: AWS profile '{profile}' not found.", file=sys.stderr)
            print(f"Available profiles are configured in ~/.aws/credentials and ~/.aws/config.", file=sys.stderr)
            print(f"\nTo set up a new profile:", file=sys.stderr)
            print(f"  aws configure --profile {profile}", file=sys.stderr)
            print(f"  # or for SSO:", file=sys.stderr)
            print(f"  aws configure sso --profile {profile}", file=sys.stderr)
            sys.exit(1)

        # Authenticate — handles SSO login if needed
        self._authenticate()

        self.iam = self.session.client("iam")
        self.account_id = self._get_account_id()
        self.region = self.session.region_name or "us-east-1"
        self.is_govcloud = self.region in GOVCLOUD_REGIONS
        self.findings: list[dict] = []

        # GovCloud warning
        if self.is_govcloud:
            self._govcloud_warning()

    def _authenticate(self):
        """Verify credentials work. If SSO token is expired, prompt login."""
        sts = self.session.client("sts")
        try:
            sts.get_caller_identity()
        except (NoCredentialsError, ClientError, UnauthorizedSSOTokenError) as e:
            error_str = str(e)
            error_code = ""
            if hasattr(e, "response"):
                error_code = e.response.get("Error", {}).get("Code", "")
            # Detect SSO-related failures: explicit SSO errors, incomplete signatures
            # from stale tokens, or expired token errors
            is_sso = (
                "SSO" in error_str
                or "UnauthorizedSSOTokenError" in type(e).__name__
                or error_code in ("IncompleteSignature", "ExpiredToken", "InvalidIdentityToken")
                or isinstance(e, NoCredentialsError)
            )

            if is_sso:
                print(f"\n[!] SSO session expired for profile '{self.profile}'. Logging in...", file=sys.stderr)
                result = subprocess.run(
                    ["aws", "sso", "login", "--profile", self.profile],
                    capture_output=False,
                )
                if result.returncode != 0:
                    print(f"\nERROR: SSO login failed for profile '{self.profile}'.", file=sys.stderr)
                    print(f"", file=sys.stderr)
                    print(f"  This usually means the profile is not configured properly.", file=sys.stderr)
                    print(f"  Check that your ~/.aws/config has the correct SSO settings:", file=sys.stderr)
                    print(f"", file=sys.stderr)
                    print(f"    [profile {self.profile}]", file=sys.stderr)
                    print(f"    sso_start_url = https://your-org.awsapps.com/start", file=sys.stderr)
                    print(f"    sso_region = us-east-1", file=sys.stderr)
                    print(f"    sso_account_id = 123456789012", file=sys.stderr)
                    print(f"    sso_role_name = YourRoleName", file=sys.stderr)
                    print(f"    region = us-east-1", file=sys.stderr)
                    print(f"", file=sys.stderr)
                    print(f"  To reconfigure this profile:", file=sys.stderr)
                    print(f"    aws configure sso --profile {self.profile}", file=sys.stderr)
                    sys.exit(1)
                # Recreate session after login
                self.session = boto3.Session(profile_name=self.profile)
                # Verify it works now
                try:
                    self.session.client("sts").get_caller_identity()
                except Exception as e2:
                    print(f"\nERROR: Still cannot authenticate after SSO login: {e2}", file=sys.stderr)
                    sys.exit(1)
            else:
                print(f"\nERROR: Cannot authenticate with profile '{self.profile}'.", file=sys.stderr)
                print(f"  {e}", file=sys.stderr)
                print(f"\nTry one of:", file=sys.stderr)
                print(f"  aws sso login --profile {self.profile}", file=sys.stderr)
                print(f"  aws configure --profile {self.profile}", file=sys.stderr)
                sys.exit(1)

        print(f"[*] Authenticated to profile '{self.profile}'", file=sys.stderr)

    def _govcloud_warning(self):
        """Print a loud warning when scanning a GovCloud account."""
        warning = """
================================================================================

  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)

         YO! This is GOVCLOUD. Be careful and shit.

    /\\_/\\
   ( O_O )  <  I'm watching you, buddy.
    > ^ <       Region:  {region}
                Account: {account}

  - This is a regulated environment (FedRAMP, ITAR, DoD, etc.)
  - All actions are read-only, but EVERYTHING is logged
  - Do NOT copy findings to non-gov systems without authorization
  - If you're not sure you should be here, STOP and ask

    /\\_/\\
   ( -_- )  <  Seriously though. Don't mess around in here.
    > ^ <

  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)
================================================================================
""".format(region=self.region, account=self.account_id)
        print(warning, file=sys.stderr)

        # Pause for confirmation if a human is at the terminal
        if sys.stdin.isatty():
            try:
                input("  Press ENTER to continue (or Ctrl+C to abort)... ")
            except KeyboardInterrupt:
                print("\n\nAborted.", file=sys.stderr)
                sys.exit(0)

    def _get_account_id(self) -> str:
        try:
            return self.session.client("sts").get_caller_identity()["Account"]
        except ClientError as e:
            print(f"ERROR: Cannot get account identity: {e}", file=sys.stderr)
            sys.exit(1)

    def scan(self) -> list[dict]:
        """Run all checks and return findings."""
        print(f"[*] Scanning AWS account {self.account_id}...", file=sys.stderr)

        self._check_credential_report()
        self._check_password_policy()
        self._check_user_policies()
        self._check_unused_roles()

        print(f"[*] Scan complete. {len(self.findings)} finding(s).", file=sys.stderr)
        return self.findings

    # --- Credential Report Checks (1-7) ---

    def _get_credential_report(self) -> list[dict]:
        """Generate and retrieve the IAM credential report."""
        print("  [+] Generating credential report...", file=sys.stderr)
        for _ in range(10):
            try:
                self.iam.generate_credential_report()
                resp = self.iam.get_credential_report()
                raw = resp["Content"]
                content = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                reader = csv.DictReader(io.StringIO(content))
                return list(reader)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ReportNotReady":
                    time.sleep(2)
                    continue
                raise
        print("  [!] Credential report not ready after retries.", file=sys.stderr)
        return []

    def _check_credential_report(self):
        """Checks 1-7: Root and user checks from credential report."""
        rows = self._get_credential_report()
        if not rows:
            return

        for row in rows:
            user = row.get("user", "")
            arn = row.get("arn", "")
            is_root = user == "<root_account>"

            # --- Check 1: Root account with access keys ---
            if is_root:
                if row.get("access_key_1_active", "").lower() == "true" or \
                   row.get("access_key_2_active", "").lower() == "true":
                    self.findings.append(finding(
                        "root_access_keys",
                        "CRITICAL",
                        arn,
                        "Root account has active access keys. Root access keys should be deleted.",
                        {"access_key_1_active": row.get("access_key_1_active"),
                         "access_key_2_active": row.get("access_key_2_active")},
                    ))

                # --- Check 2: Root account without MFA ---
                if row.get("mfa_active", "").lower() != "true":
                    self.findings.append(finding(
                        "root_no_mfa",
                        "CRITICAL",
                        arn,
                        "Root account does not have MFA enabled.",
                    ))
                continue  # Skip remaining user checks for root

            # --- Check 3: Users without MFA ---
            has_password = row.get("password_enabled", "").lower() == "true"
            has_mfa = row.get("mfa_active", "").lower() == "true"
            if has_password and not has_mfa:
                self.findings.append(finding(
                    "user_no_mfa",
                    "HIGH",
                    arn,
                    f"User '{user}' has console access but MFA is not enabled.",
                    {"user": user, "password_enabled": True, "mfa_active": False},
                ))

            # --- Check 4: Stale access keys (>90 days since rotation) ---
            for key_num in ("1", "2"):
                active = row.get(f"access_key_{key_num}_active", "").lower() == "true"
                rotated = row.get(f"access_key_{key_num}_last_rotated", "")
                if active:
                    age = days_since(rotated)
                    if age is not None and age > STALE_DAYS:
                        self.findings.append(finding(
                            "stale_access_key",
                            "HIGH",
                            arn,
                            f"User '{user}' access key {key_num} has not been rotated in {age} days.",
                            {"user": user, "key_number": key_num, "last_rotated": rotated, "age_days": age},
                        ))

                    # --- Check 5: Unused access keys ---
                    last_used = row.get(f"access_key_{key_num}_last_used_date", "")
                    if last_used in ("N/A", "no_information", ""):
                        self.findings.append(finding(
                            "unused_access_key",
                            "MEDIUM",
                            arn,
                            f"User '{user}' access key {key_num} is active but has never been used.",
                            {"user": user, "key_number": key_num, "last_used": last_used},
                        ))

            # --- Check 6: Console password never used (>90 days) ---
            if has_password:
                last_login = row.get("password_last_used", "")
                login_age = days_since(last_login)
                if login_age is not None and login_age > STALE_DAYS:
                    self.findings.append(finding(
                        "stale_console_login",
                        "MEDIUM",
                        arn,
                        f"User '{user}' has not logged into the console in {login_age} days.",
                        {"user": user, "last_login": last_login, "age_days": login_age},
                    ))

            # --- Check 7: Stale console password ---
            if has_password:
                pw_changed = row.get("password_last_changed", "")
                pw_age = days_since(pw_changed)
                if pw_age is not None and pw_age > STALE_DAYS:
                    self.findings.append(finding(
                        "stale_password",
                        "LOW",
                        arn,
                        f"User '{user}' has not changed their password in {pw_age} days.",
                        {"user": user, "last_changed": pw_changed, "age_days": pw_age},
                    ))

    # --- Password Policy Check (12) ---

    def _check_password_policy(self):
        """Check 12: Account password policy compliance."""
        print("  [+] Checking password policy...", file=sys.stderr)
        try:
            policy = self.iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                self.findings.append(finding(
                    "no_password_policy",
                    "HIGH",
                    f"arn:aws:iam::{self.account_id}:account",
                    "No custom password policy is configured. AWS default policy is in use.",
                ))
                return
            raise

        issues = []
        min_len = policy.get("MinimumPasswordLength", 0)
        if min_len < CIS_MIN_PASSWORD_LENGTH:
            issues.append(f"Minimum length is {min_len} (should be >= {CIS_MIN_PASSWORD_LENGTH})")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("Does not require uppercase characters")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("Does not require lowercase characters")
        if not policy.get("RequireNumbers", False):
            issues.append("Does not require numbers")
        if not policy.get("RequireSymbols", False):
            issues.append("Does not require symbols")
        if not policy.get("MaxPasswordAge", 0):
            issues.append("No password expiration configured")

        if issues:
            self.findings.append(finding(
                "weak_password_policy",
                "HIGH",
                f"arn:aws:iam::{self.account_id}:account",
                f"Password policy does not meet CIS benchmarks: {'; '.join(issues)}",
                {"policy": policy, "issues": issues},
            ))

    # --- User Policy Checks (8-10) ---

    def _check_user_policies(self):
        """Checks 8-10: Directly attached policies, inline policies, overprivileged users."""
        print("  [+] Checking user policies...", file=sys.stderr)
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                arn = user["Arn"]

                # Check 9: Inline policies
                try:
                    inline = self.iam.list_user_policies(UserName=username)
                    inline_names = inline.get("PolicyNames", [])
                    if inline_names:
                        self.findings.append(finding(
                            "inline_user_policy",
                            "MEDIUM",
                            arn,
                            f"User '{username}' has {len(inline_names)} inline policy(ies). Use managed policies via roles instead.",
                            {"user": username, "inline_policies": inline_names},
                        ))
                except ClientError:
                    pass

                # Check 8 + 10: Attached policies
                try:
                    attached = self.iam.list_attached_user_policies(UserName=username)
                    attached_policies = attached.get("AttachedPolicies", [])

                    if attached_policies:
                        # Check 8: Any directly attached policy
                        self.findings.append(finding(
                            "directly_attached_policy",
                            "MEDIUM",
                            arn,
                            f"User '{username}' has {len(attached_policies)} directly attached policy(ies). Attach policies to roles or groups instead.",
                            {"user": username, "policies": [p["PolicyName"] for p in attached_policies]},
                        ))

                        # Check 10: Overprivileged
                        for pol in attached_policies:
                            if pol["PolicyArn"] in OVERPRIVILEGED_POLICIES:
                                self.findings.append(finding(
                                    "overprivileged_user",
                                    "HIGH",
                                    arn,
                                    f"User '{username}' has overprivileged policy '{pol['PolicyName']}' directly attached.",
                                    {"user": username, "policy_arn": pol["PolicyArn"], "policy_name": pol["PolicyName"]},
                                ))
                except ClientError:
                    pass

    # --- Role Checks (11) ---

    def _check_unused_roles(self):
        """Check 11: IAM roles not used in >90 days."""
        print("  [+] Checking unused roles...", file=sys.stderr)
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                name = role["RoleName"]
                arn = role["Arn"]

                # Skip AWS service-linked roles
                if role.get("Path", "").startswith("/aws-service-role/"):
                    continue

                last_used_info = role.get("RoleLastUsed", {})
                last_used_date = last_used_info.get("LastUsedDate")

                if last_used_date:
                    age = (datetime.now(timezone.utc) - last_used_date.replace(tzinfo=timezone.utc)
                           if last_used_date.tzinfo is None else
                           datetime.now(timezone.utc) - last_used_date).days
                    if age > STALE_DAYS:
                        self.findings.append(finding(
                            "unused_role",
                            "MEDIUM",
                            arn,
                            f"Role '{name}' has not been used in {age} days.",
                            {"role": name, "last_used": last_used_date.isoformat(), "age_days": age},
                        ))
                else:
                    # Role has never been used
                    create_date = role.get("CreateDate")
                    if create_date:
                        created_age = (datetime.now(timezone.utc) - create_date.replace(tzinfo=timezone.utc)
                                       if create_date.tzinfo is None else
                                       datetime.now(timezone.utc) - create_date).days
                        if created_age > STALE_DAYS:
                            self.findings.append(finding(
                                "unused_role",
                                "MEDIUM",
                                arn,
                                f"Role '{name}' was created {created_age} days ago and has never been used.",
                                {"role": name, "created": create_date.isoformat(), "never_used": True, "age_days": created_age},
                            ))


def main():
    parser = argparse.ArgumentParser(description="AWS IAM Hygiene Scanner")
    parser.add_argument("--profile", required=True, help="AWS CLI profile name")
    parser.add_argument("--output", default=None, help="Output file path (default: stdout)")
    args = parser.parse_args()

    scanner = IAMScanner(args.profile)
    findings = scanner.scan()

    result = {
        "account_id": scanner.account_id,
        "region": scanner.region,
        "is_govcloud": scanner.is_govcloud,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "total_findings": len(findings),
        "summary": {
            "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in findings if f["severity"] == "LOW"),
        },
        "findings": findings,
    }

    output = json.dumps(result, indent=2, default=str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"[*] Findings written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
