"""
SankofahEye — Input Validator
AfriWealth Cyber Intelligence
"""

import re


def validate_domain(domain: str) -> tuple[bool, str]:
    """
    Validate a domain name. Returns (is_valid, cleaned_domain).
    Strips http/https/www prefixes automatically.
    """
    domain = domain.strip().lower()
    # Strip protocol
    domain = re.sub(r'^https?://', '', domain)
    # Strip trailing slash
    domain = domain.rstrip('/')
    # Strip www.
    if domain.startswith('www.'):
        domain = domain[4:]

    pattern = r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    if re.match(pattern, domain):
        return True, domain
    return False, domain


def validate_org(org: str) -> tuple[bool, str]:
    """Basic org name validation — just strips whitespace and checks non-empty."""
    org = org.strip()
    if len(org) < 2:
        return False, org
    return True, org
