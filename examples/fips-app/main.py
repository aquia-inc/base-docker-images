"""Minimal application demonstrating FIPS approved mode in a derived image.

Nothing here configures OpenSSL. The FIPS base image exports OPENSSL_CONF and
OPENSSL_MODULES, so approved mode is already in force by the time this runs.

The MD5 call is deliberate: it is expected to fail. That failure is the proof
that approved mode is actually being enforced rather than merely available.
"""

import hashlib
import ssl
import sys


def main() -> int:
    print(f"OpenSSL in use: {ssl.OPENSSL_VERSION}")

    digest = hashlib.sha256(b"fips-check").hexdigest()
    print(f"SHA-256 (approved):     ok, {digest[:32]}...")

    try:
        hashlib.md5(b"fips-check")
    except ValueError as exc:
        # Python raises _hashlib.UnsupportedDigestmodError, a ValueError
        # subclass, when the FIPS provider refuses a non-approved digest.
        print(f"MD5 (non-approved):     correctly refused ({type(exc).__name__})")
        return 0

    print("MD5 (non-approved):     SUCCEEDED - approved mode is NOT enforced", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
