#!/usr/bin/env python3
"""AWS IAM Hygiene Scanner — Read-only IAM security checks.

Scans an AWS account via a CLI profile and outputs JSON findings.
All operations are read-only (list/get/generate-credential-report).

Usage:
    python scanner.py --profile <aws-profile-name>
    python scanner.py --profile <aws-profile-name> --output findings.json
    python scanner.py --profile <aws-profile-name> --days 60 --update-intel
"""

import argparse
import base64
import csv
import io
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound, UnauthorizedSSOTokenError


# --- Constants ---
GOVCLOUD_REGIONS = {"us-gov-west-1", "us-gov-east-1"}
OVERPRIVILEGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}
CIS_MIN_PASSWORD_LENGTH = 14
RISK_INTEL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "risk_intel.json")
RISK_INTEL_URL = "https://raw.githubusercontent.com/Saronic-Security/aws-iam-auditor/master/risk_intel.json"


# --- ANSI Colors ---
class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def enabled():
        return sys.stderr.isatty()

    @classmethod
    def red(cls, s): return f"{cls.RED}{s}{cls.RESET}" if cls.enabled() else s
    @classmethod
    def yellow(cls, s): return f"{cls.YELLOW}{s}{cls.RESET}" if cls.enabled() else s
    @classmethod
    def green(cls, s): return f"{cls.GREEN}{s}{cls.RESET}" if cls.enabled() else s
    @classmethod
    def cyan(cls, s): return f"{cls.CYAN}{s}{cls.RESET}" if cls.enabled() else s
    @classmethod
    def bold(cls, s): return f"{cls.BOLD}{s}{cls.RESET}" if cls.enabled() else s
    @classmethod
    def dim(cls, s): return f"{cls.DIM}{s}{cls.RESET}" if cls.enabled() else s


def log(msg: str, level: str = "info"):
    colors = {
        "critical": C.red,
        "high": C.red,
        "warning": C.yellow,
        "success": C.green,
        "info": C.cyan,
        "dim": C.dim,
    }
    fn = colors.get(level, C.cyan)
    print(fn(msg), file=sys.stderr)


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


def load_risk_intel(update: bool = False) -> dict:
    """Load risk intelligence data. Optionally fetch latest from GitHub first."""
    if update:
        log("[*] Fetching latest risk intelligence...")
        try:
            req = urllib.request.Request(RISK_INTEL_URL, headers={"User-Agent": "aws-iam-auditor/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                remote_data = json.loads(resp.read().decode("utf-8"))
            remote_ver = remote_data.get("_metadata", {}).get("version", "0")
            local_data = {}
            if os.path.exists(RISK_INTEL_FILE):
                with open(RISK_INTEL_FILE, "r", encoding="utf-8") as f:
                    local_data = json.load(f)
            local_ver = local_data.get("_metadata", {}).get("version", "0")
            if remote_ver >= local_ver:
                with open(RISK_INTEL_FILE, "w", encoding="utf-8") as f:
                    json.dump(remote_data, f, indent=2)
                log(f"  [+] Risk intel updated to v{remote_ver} ({remote_data['_metadata']['last_updated']})", "success")
            else:
                log(f"  [+] Local risk intel v{local_ver} is already current", "success")
        except Exception as e:
            log(f"  [!] Could not fetch remote intel ({e}), using local copy", "warning")

    if os.path.exists(RISK_INTEL_FILE):
        with open(RISK_INTEL_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        meta = data.get("_metadata", {})
        log(f"[*] Risk intel loaded: v{meta.get('version', '?')} ({meta.get('last_updated', 'unknown')})")
        return data
    else:
        log("[!] No risk_intel.json found. Findings will not include threat context.", "warning")
        return {}


def enrich_finding(f: dict, intel: dict) -> dict:
    """Attach risk intelligence context to a finding."""
    check = f["check"]
    if check in intel:
        ctx = intel[check]
        f["risk_context"] = {
            "cis_control": ctx.get("cis_control", "N/A"),
            "priv_escalation": ctx.get("priv_escalation", False),
            "data_leakage": ctx.get("data_leakage", False),
            "lateral_movement": ctx.get("lateral_movement", False),
            "initial_access": ctx.get("initial_access", False),
            "mitre_attack": ctx.get("mitre_attack", []),
            "real_incidents": ctx.get("real_incidents", []),
            "threat_summary": ctx.get("threat_summary", ""),
        }
    return f


class IAMScanner:
    def __init__(self, profile: str, stale_days: int = 90):
        self.profile = profile
        self.stale_days = stale_days
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
            is_sso = (
                "SSO" in error_str
                or "UnauthorizedSSOTokenError" in type(e).__name__
                or error_code in ("IncompleteSignature", "ExpiredToken", "InvalidIdentityToken")
                or isinstance(e, NoCredentialsError)
            )

            if is_sso:
                log(f"\n[!] SSO session expired for profile '{self.profile}'. Logging in...", "warning")
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
                self.session = boto3.Session(profile_name=self.profile)
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

        log(f"[*] Authenticated to profile '{self.profile}'", "success")

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
        log(f"[*] Scanning AWS account {C.bold(self.account_id)} (stale threshold: {self.stale_days} days)...")

        self._check_credential_report()
        self._check_password_policy()
        self._check_user_policies()
        self._check_unused_roles()
        self._check_wildcard_trust_policies()

        if self.findings:
            crit = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
            high = sum(1 for f in self.findings if f["severity"] == "HIGH")
            med = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
            low = sum(1 for f in self.findings if f["severity"] == "LOW")
            log(f"[*] Scan complete: {C.red(f'{crit} CRITICAL')}  {C.yellow(f'{high} HIGH')}  {med} MEDIUM  {low} LOW")
        else:
            self._clean_scan()

        return self.findings

    def _clean_scan(self):
        """Celebrate a clean scan."""
        msg = """
================================================================================

  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)

              ALL CLEAR! No findings detected.

    /\\_/\\
   ( ^w^ )  <  This account is looking good!
    > ^ <

  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)  ~(=^..^)
================================================================================
"""
        log(msg, "success")

    # --- Credential Report Checks (1-7) ---

    def _get_credential_report(self) -> list[dict]:
        """Generate and retrieve the IAM credential report."""
        log("  [+] Generating credential report...", "dim")
        for _ in range(10):
            try:
                self.iam.generate_credential_report()
                resp = self.iam.get_credential_report()
                raw = resp["Content"]
                content = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                reader = csv.DictReader(io.StringIO(content))
                return list(reader)
            except ClientError as e:
                if e.response["Error"]["Code"] in ("ReportNotReady", "ReportInProgress"):
                    time.sleep(2)
                    continue
                raise
        log("  [!] Credential report not ready after retries.", "warning")
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
                        "root_access_keys", "CRITICAL", arn,
                        "Root account has active access keys. Root access keys should be deleted.",
                        {"access_key_1_active": row.get("access_key_1_active"),
                         "access_key_2_active": row.get("access_key_2_active")},
                    ))

                # --- Check 2: Root account without MFA ---
                if row.get("mfa_active", "").lower() != "true":
                    self.findings.append(finding(
                        "root_no_mfa", "CRITICAL", arn,
                        "Root account does not have MFA enabled.",
                    ))
                continue

            # --- Check 3: Users without MFA ---
            has_password = row.get("password_enabled", "").lower() == "true"
            has_mfa = row.get("mfa_active", "").lower() == "true"
            if has_password and not has_mfa:
                self.findings.append(finding(
                    "user_no_mfa", "HIGH", arn,
                    f"User '{user}' has console access but MFA is not enabled.",
                    {"user": user, "password_enabled": True, "mfa_active": False},
                ))

            # --- Check 4 & 5: Access key checks ---
            for key_num in ("1", "2"):
                active = row.get(f"access_key_{key_num}_active", "").lower() == "true"
                if not active:
                    continue

                rotated = row.get(f"access_key_{key_num}_last_rotated", "")
                age = days_since(rotated)
                if age is not None and age > self.stale_days:
                    self.findings.append(finding(
                        "stale_access_key", "HIGH", arn,
                        f"User '{user}' access key {key_num} has not been rotated in {age} days.",
                        {"user": user, "key_number": key_num, "last_rotated": rotated, "age_days": age},
                    ))

                last_used = row.get(f"access_key_{key_num}_last_used_date", "")
                if last_used in ("N/A", "no_information", ""):
                    self.findings.append(finding(
                        "unused_access_key", "MEDIUM", arn,
                        f"User '{user}' access key {key_num} is active but has never been used.",
                        {"user": user, "key_number": key_num, "last_used": last_used},
                    ))

            # --- Check: Multiple active access keys ---
            key1_active = row.get("access_key_1_active", "").lower() == "true"
            key2_active = row.get("access_key_2_active", "").lower() == "true"
            if key1_active and key2_active:
                self.findings.append(finding(
                    "multiple_active_keys", "MEDIUM", arn,
                    f"User '{user}' has two active access keys. This is almost always a mistake — one should be deactivated.",
                    {"user": user},
                ))

            # --- Check 6: Console password never used (>stale_days) ---
            if has_password:
                last_login = row.get("password_last_used", "")
                login_age = days_since(last_login)
                if login_age is not None and login_age > self.stale_days:
                    self.findings.append(finding(
                        "stale_console_login", "MEDIUM", arn,
                        f"User '{user}' has not logged into the console in {login_age} days.",
                        {"user": user, "last_login": last_login, "age_days": login_age},
                    ))

            # --- Check 7: Stale console password ---
            if has_password:
                pw_changed = row.get("password_last_changed", "")
                pw_age = days_since(pw_changed)
                if pw_age is not None and pw_age > self.stale_days:
                    self.findings.append(finding(
                        "stale_password", "LOW", arn,
                        f"User '{user}' has not changed their password in {pw_age} days.",
                        {"user": user, "last_changed": pw_changed, "age_days": pw_age},
                    ))

    # --- Password Policy Check ---

    def _check_password_policy(self):
        log("  [+] Checking password policy...", "dim")
        try:
            policy = self.iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                self.findings.append(finding(
                    "no_password_policy", "HIGH",
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
                "weak_password_policy", "HIGH",
                f"arn:aws:iam::{self.account_id}:account",
                f"Password policy does not meet CIS benchmarks: {'; '.join(issues)}",
                {"policy": policy, "issues": issues},
            ))

    # --- User Policy Checks (8-10) ---

    def _check_user_policies(self):
        log("  [+] Checking user policies...", "dim")
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                arn = user["Arn"]

                try:
                    inline = self.iam.list_user_policies(UserName=username)
                    inline_names = inline.get("PolicyNames", [])
                    if inline_names:
                        self.findings.append(finding(
                            "inline_user_policy", "MEDIUM", arn,
                            f"User '{username}' has {len(inline_names)} inline policy(ies). Use managed policies via roles instead.",
                            {"user": username, "inline_policies": inline_names},
                        ))
                except ClientError:
                    pass

                try:
                    attached = self.iam.list_attached_user_policies(UserName=username)
                    attached_policies = attached.get("AttachedPolicies", [])
                    if attached_policies:
                        self.findings.append(finding(
                            "directly_attached_policy", "MEDIUM", arn,
                            f"User '{username}' has {len(attached_policies)} directly attached policy(ies). Attach policies to roles or groups instead.",
                            {"user": username, "policies": [p["PolicyName"] for p in attached_policies]},
                        ))
                        for pol in attached_policies:
                            if pol["PolicyArn"] in OVERPRIVILEGED_POLICIES:
                                self.findings.append(finding(
                                    "overprivileged_user", "HIGH", arn,
                                    f"User '{username}' has overprivileged policy '{pol['PolicyName']}' directly attached.",
                                    {"user": username, "policy_arn": pol["PolicyArn"], "policy_name": pol["PolicyName"]},
                                ))
                except ClientError:
                    pass

    # --- Role Checks ---

    def _check_unused_roles(self):
        log("  [+] Checking unused roles...", "dim")
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                name = role["RoleName"]
                arn = role["Arn"]

                if role.get("Path", "").startswith("/aws-service-role/"):
                    continue

                last_used_info = role.get("RoleLastUsed", {})
                last_used_date = last_used_info.get("LastUsedDate")

                if last_used_date:
                    age = (datetime.now(timezone.utc) - last_used_date.replace(tzinfo=timezone.utc)
                           if last_used_date.tzinfo is None else
                           datetime.now(timezone.utc) - last_used_date).days
                    if age > self.stale_days:
                        self.findings.append(finding(
                            "unused_role", "MEDIUM", arn,
                            f"Role '{name}' has not been used in {age} days.",
                            {"role": name, "last_used": last_used_date.isoformat(), "age_days": age},
                        ))
                else:
                    create_date = role.get("CreateDate")
                    if create_date:
                        created_age = (datetime.now(timezone.utc) - create_date.replace(tzinfo=timezone.utc)
                                       if create_date.tzinfo is None else
                                       datetime.now(timezone.utc) - create_date).days
                        if created_age > self.stale_days:
                            self.findings.append(finding(
                                "unused_role", "MEDIUM", arn,
                                f"Role '{name}' was created {created_age} days ago and has never been used.",
                                {"role": name, "created": create_date.isoformat(), "never_used": True, "age_days": created_age},
                            ))

    # --- NEW: Wildcard Trust Policies ---

    def _check_wildcard_trust_policies(self):
        """Check for roles with Principal: * in their trust policy — anyone can assume them."""
        log("  [+] Checking role trust policies for wildcards...", "dim")
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                name = role["RoleName"]
                arn = role["Arn"]

                if role.get("Path", "").startswith("/aws-service-role/"):
                    continue

                trust = role.get("AssumeRolePolicyDocument", {})
                for stmt in trust.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal", {})
                    # Check for "*" or {"AWS": "*"}
                    is_wildcard = (
                        principal == "*"
                        or principal.get("AWS") == "*"
                        or (isinstance(principal.get("AWS"), list) and "*" in principal["AWS"])
                    )
                    if is_wildcard:
                        # Check if there's a condition that restricts it
                        has_condition = bool(stmt.get("Condition"))
                        severity = "HIGH" if has_condition else "CRITICAL"
                        detail = f"Role '{name}' has a wildcard trust policy (Principal: *). "
                        if has_condition:
                            detail += "A Condition clause exists but should be reviewed."
                        else:
                            detail += "ANYONE on the internet can assume this role."
                        self.findings.append(finding(
                            "wildcard_trust_policy", severity, arn, detail,
                            {"role": name, "trust_policy": trust, "has_condition": has_condition},
                        ))
                        break  # One finding per role



def main():
    parser = argparse.ArgumentParser(description="AWS IAM Hygiene Scanner")
    parser.add_argument("--profile", required=True, help="AWS CLI profile name")
    parser.add_argument("--output", default=None, help="Output file path (default: stdout)")
    parser.add_argument("--days", type=int, default=90, help="Stale threshold in days (default: 90)")
    parser.add_argument("--update-intel", action="store_true", help="Fetch latest risk intelligence before scanning")
    args = parser.parse_args()

    # Load risk intelligence before scanning
    intel = load_risk_intel(update=args.update_intel)

    scan_start = time.time()
    scanner = IAMScanner(args.profile, stale_days=args.days)
    findings = scanner.scan()
    scan_duration = time.time() - scan_start

    # Enrich findings with threat context
    findings = [enrich_finding(f, intel) for f in findings]
    priv_esc_count = sum(1 for f in findings if f.get("risk_context", {}).get("priv_escalation"))
    data_leak_count = sum(1 for f in findings if f.get("risk_context", {}).get("data_leakage"))

    result = {
        "account_id": scanner.account_id,
        "region": scanner.region,
        "is_govcloud": scanner.is_govcloud,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "scan_duration_seconds": round(scan_duration, 1),
        "stale_threshold_days": args.days,
        "profile": args.profile,
        "intel_version": intel.get("_metadata", {}).get("version", "unknown"),
        "intel_updated": intel.get("_metadata", {}).get("last_updated", "unknown"),
        "total_findings": len(findings),
        "summary": {
            "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in findings if f["severity"] == "LOW"),
            "priv_escalation_risks": priv_esc_count,
            "data_leakage_risks": data_leak_count,
        },
        "findings": findings,
    }

    log(f"[*] {C.red(f'{priv_esc_count} priv escalation')} / {C.yellow(f'{data_leak_count} data leakage')} risk(s) flagged")
    log(f"[*] Completed in {C.bold(f'{scan_duration:.1f}s')}", "success")

    output = json.dumps(result, indent=2, default=str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        log(f"[*] Findings written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
