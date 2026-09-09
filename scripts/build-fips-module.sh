#!/bin/sh
# Build a CMVP-validated OpenSSL FIPS Provider from unmodified upstream source.
#
# Shared by Dockerfile.fips-base (FIPS 140-2, module 3.0.9, certificates #4282
# and #4811) and Dockerfile.fips-140-3 (FIPS 140-3, module 3.1.2, certificate
# #4985). The compile method lives here exactly once so that a correction to it
# cannot land in one image and be missed in the other.
#
# WHY THIS SCRIPT MAY NOT BE "IMPROVED"
# -------------------------------------
# Building the Module here is a post-validation recompilation. The FIPS 140-3
# CMVP Management Manual governs that directly:
#
#   Section 7.9.2 (User):
#     "A user may not modify a validated module. Any user modifications
#      invalidate a module validation."
#
#   Footnote 5 to 7.9.2, the exception relied on here:
#     "A user may post-validation recompile a module if the unmodified source
#      code is available and the module's Security Policy provides specific
#      guidance on acceptable recompilation methods to be followed as a
#      specific exception to this guidance. The methods in the Security Policy
#      must be followed without modification to comply with this guidance."
#
# https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS-140-3-CMVP%20Management%20Manual.pdf
#
# Both Security Policies prescribe the identical three commands, and this
# script issues exactly those and nothing else:
#
#   $ ./Configure enable-fips
#   $ make
#   $ make install_fips
#
# Do NOT append Configure options. Hardening-looking flags such as
# "no-ssl3 no-legacy no-comp no-err" change the compilation method away from
# the one the Security Policy prescribes and forfeit the footnote 5 exception.
#
# The SHA-256 check below is what substantiates "unmodified source code". It is
# a hard failure, never a warning.
#
# Compiler and platform: FIPS 140-2 Security Policy Appendix B records that,
# per FIPS 140-2 Implementation Guidance G.5, "compliance is maintained for
# other versions of the respective operational environments and compilers
# provided the module source code is unchanged", so building with the
# distribution toolchain rather than the exact tested compiler is permitted.
#
# Usage: build-fips-module.sh <openssl-version> <sha256> [staging-dir]

set -eu

VERSION="${1:-}"
SHA256="${2:-}"
STAGING="${3:-/staging}"

if [ -z "$VERSION" ] || [ -z "$SHA256" ]; then
    echo "usage: $0 <openssl-version> <sha256> [staging-dir]" >&2
    exit 2
fi

# Superseded OpenSSL releases are served from a per-series /old/ directory.
# The URL is only a transport detail; the SHA-256 below is the integrity
# control, so a mirror change cannot weaken this.
SERIES="$(echo "$VERSION" | cut -d. -f1-2)"
TARBALL="openssl-${VERSION}.tar.gz"
URL="https://www.openssl.org/source/old/${SERIES}/${TARBALL}"

WORKDIR="${TMPDIR:-/tmp}/fips-module-build"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo "build-fips-module: fetching ${URL}"
wget -q -O "$TARBALL" "$URL"

# Verified from a file rather than a pipeline so the check cannot be masked by
# a shell that reports only the exit status of the last command in a pipe.
echo "build-fips-module: verifying source integrity"
printf '%s  %s\n' "$SHA256" "$TARBALL" > "${TARBALL}.sha256"
sha256sum -c "${TARBALL}.sha256"

tar -xzf "$TARBALL"
cd "openssl-${VERSION}"

# The Security Policy build method, verbatim. See the header before editing.
echo "build-fips-module: configuring (enable-fips)"
./Configure enable-fips

echo "build-fips-module: compiling"
make -j"$(nproc)"

echo "build-fips-module: installing the FIPS Provider only"
make install_fips

# OpenSSL installs into lib or lib64 depending on the target, so resolve the
# real location once here and hand the caller a fixed, arch-independent layout.
module="$(find /usr/local -type f -name fips.so | head -n 1)"
if [ -z "$module" ]; then
    echo "build-fips-module: install_fips did not produce fips.so" >&2
    exit 1
fi

mkdir -p "${STAGING}/ossl-modules"
cp "$module" "${STAGING}/ossl-modules/fips.so"

echo "build-fips-module: staged ${module} -> ${STAGING}/ossl-modules/fips.so"
sha256sum "${STAGING}/ossl-modules/fips.so"

# Leave no source tree behind; this runs in a builder stage but keeping it
# tidy makes the staged output unambiguous.
cd /
rm -rf "$WORKDIR"

echo "build-fips-module: done (OpenSSL ${VERSION} FIPS Provider)"
