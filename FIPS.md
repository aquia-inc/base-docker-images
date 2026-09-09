# FIPS Base Images

This repository publishes two FIPS images. Both load a CMVP-validated OpenSSL
FIPS Provider in approved mode; they differ in which validation they are built
against.

| | `fips-140-3` | `fips-base` |
|---|---|---|
| Standard | FIPS 140-3 | FIPS 140-2 |
| CMVP certificate | [#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985) | [#4282](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282) / [#4811](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4811) |
| Module version | 3.1.2 | 3.0.9 |
| Certificate sunset | 2030-03-10 | **2026-09-21** |
| Base distribution | Wolfi (glibc) | Wolfi Alpine (musl) |
| Status | **Current** | **Deprecated** |

**New workloads should use `fips-140-3`.**

## Deprecation of `fips-base`

> **In short:** the FIPS 140-2 provider behind `fips-base` (OpenSSL 3.0.9) loses
> its NIST certificates on **2026-09-21**, so it is being replaced by the FIPS
> 140-3 provider (OpenSSL 3.1.2, `fips-140-3`). **No image reference change is
> required:** at the cutover the `fips-base` tags are republished onto the FIPS
> 140-3 image, so an existing `FROM ...fips-base...` keeps working and
> transparently moves to 140-3. Because the 140-3 image is Wolfi/glibc where
> `fips-base` was Alpine/musl, two things need a check: native binaries compiled
> on `fips-base` (Go cgo, C extensions) must be rebuilt, and the default user
> changes from `nobody` (65534) to `nonroot` (65532). Interpreted runtimes and
> OpenSSL-CLI usage are unaffected. Detail is in
> [Migrating](#migrating-from-fips-base-to-fips-140-3).

The FIPS 140-2 certificates behind `fips-base` both reach their sunset date on
**2026-09-21**, after which they move to the CMVP Historical list. CMVP's
position on Historical modules is that federal agencies "should not include
these in new systems but can be procured for legacy systems", with continued
use subject to the agency's own risk determination.

Accordingly:

- Until 2026-09-21, `fips-base` continues to build and publish on the FIPS 140-2
  provider (OpenSSL 3.0.9) with daily CVE patches.
- On 2026-09-21, the cutover republishes the `fips-base` tags (`:latest` and the
  version tags) onto the FIPS 140-3 image. An existing `fips-base` reference
  keeps resolving and transparently moves to the 140-3 provider - no consumer
  Dockerfile change is required.
- Tags published before the cutover remain pullable from GHCR indefinitely.

The two images are deliberately kept close so that the cutover needs no image
reference change; the only consumer-visible differences are the base OS (musl to
glibc) and the default user. See [Migrating](#migrating-from-fips-base-to-fips-140-3).

## How these images are built

Only the FIPS Provider itself (`fips.so`) is compiled from the validated
OpenSSL source. `libcrypto` and `libssl` come from the distribution and are
upgraded on every rebuild.

This is not a shortcut. The Security Policy defines the module boundary as the
provider alone:

> "The logical cryptographic boundary of the Module is the FIPS Provider, a
> dynamically loadable library."

and OpenSSL's own [`fips_module`](https://docs.openssl.org/3.5/man7/fips_module/)
documentation states:

> "Normally, it is possible to utilize a FIPS provider constructed from one of
> the validated versions alongside `libcrypto` and `libssl` compiled from any
> supported release from OpenSSL 3.0 onwards. ... This flexibility enables you
> to address bug fixes and CVEs that fall outside the FIPS boundary."

The practical effect is significant. An image that compiles and ships the whole
validated OpenSSL tree carries every out-of-boundary CVE of that release, and
package scanners cannot see them, because a source build leaves no package
metadata behind. Building only the module removes that entire class of finding
while leaving the validated component untouched.

### The build method is fixed by the Security Policy

Compiling the module here is a post-validation recompilation. The
[FIPS 140-3 CMVP Management Manual](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS-140-3-CMVP%20Management%20Manual.pdf)
section 7.9.2 states that "a user may not modify a validated module", and its
footnote 5 gives the only exception:

> "A user may post-validation recompile a module if the unmodified source code
> is available and the module's Security Policy provides specific guidance on
> acceptable recompilation methods to be followed as a specific exception to
> this guidance. **The methods in the Security Policy must be followed without
> modification** to comply with this guidance."

Both Security Policies prescribe the same three commands, and
`scripts/build-fips-module.sh` issues exactly those and nothing else:

```sh
./Configure enable-fips
make
make install_fips
```

Two consequences worth knowing before editing anything:

- **Do not add `Configure` options.** Hardening-looking flags such as
  `no-ssl3 no-legacy no-comp no-err` change the compilation method away from
  the prescribed one and forfeit the footnote 5 exception.
- **The source tarball is verified against the SHA-256 published by OpenSSL.**
  That check is what substantiates "unmodified source code", so it is a hard
  build failure rather than a warning.

Building with the distribution toolchain rather than the exact tested compiler
is explicitly permitted: FIPS 140-2 Security Policy Appendix B records that per
Implementation Guidance G.5, "compliance is maintained for other versions of
the respective operational environments and compilers provided the module
source code is unchanged".

## What may and may not be claimed

Neither image runs on an operational environment listed on its certificate.
The tested environments are Ubuntu 22.04.1, Debian 11.5, FreeBSD 13.1,
Windows 10 and macOS 11.5.2.

Both images therefore rely on **user affirmation** under Management Manual
7.9.2, whose stated limit is:

> "The user may affirm that the module works correctly in the new OE if the
> porting rules are followed. However, the CMVP makes no statement as to the
> correct operation of the module or the security strengths of the generated
> keys when ported and executed in an OE not listed on the validation
> certificate."

Concretely:

- **Correct:** "built from the CMVP-validated source per the Security Policy,
  user-affirmed for this operating environment".
- **Not correct:** "FIPS 140-3 validated on Wolfi". No such validation entry
  exists.

`fips-140-3` runs on Wolfi, which is glibc and so in the same OS family as the
tested Debian/Ubuntu environments; Management Manual footnote 4 gives "OSs of
the same 'family'" as an example of compatibility. `fips-base` runs on musl,
which is a weaker compatibility argument. That base was left unchanged
deliberately, because swapping the C library underneath existing consumers
during a short migration window would be more disruptive than the argument is
worth.

## Verifying FIPS mode yourself

Both images are configured with `default_properties = fips=yes`, so approved
mode is enforced rather than merely available. Every check below runs in the
published image with no extra configuration.

```sh
# The FIPS provider must be present and active
docker run --rm ghcr.io/aquia-inc/base-docker-images/fips-140-3:latest \
    openssl list -providers

# Module integrity: HMAC-SHA2-256 over fips.so vs fipsmodule.cnf
docker run --rm ghcr.io/aquia-inc/base-docker-images/fips-140-3:latest \
    openssl fipsinstall \
        -module /opt/openssl-fips/ossl-modules/fips.so \
        -in /opt/openssl-fips/fipsmodule.cnf -verify

# A non-approved algorithm must FAIL. This is the check that matters:
# a module that is loaded but not enforcing still passes everything above.
docker run --rm ghcr.io/aquia-inc/base-docker-images/fips-140-3:latest \
    sh -c 'echo x | openssl dgst -md5'
```

Expected output of the first command:

```
Providers:
  base
    name: OpenSSL Base Provider
    status: active
  fips
    name: OpenSSL FIPS Provider
    version: 3.1.2
    status: active
```

The MD5 command is expected to fail with `unsupported`. If it succeeds, the
image is not enforcing approved mode.

Enforcement is inherited by anything built on these images, not just the
`openssl` CLI. In a derived image that installs Python, `hashlib.sha256()`
works and `hashlib.md5()` raises `UnsupportedDigestmodError`.

The same assertions are encoded as container structure tests in
`tests/container-structure/fips-140-3.yaml` and
`tests/container-structure/fips-base.yaml`, and are additionally enforced at
build time so a misconfiguration fails the build rather than shipping.

Each image also records its provenance at `/tmp/versions.txt`:

```sh
docker run --rm ghcr.io/aquia-inc/base-docker-images/fips-140-3:latest \
    cat /tmp/versions.txt
```

## Migrating from `fips-base` to `fips-140-3`

For most consumers no change is required. At the 2026-09-21 cutover the
`fips-base` tags are republished onto the FIPS 140-3 image, so an existing
reference keeps working and moves to 140-3 automatically:

```dockerfile
# keeps working - resolves to the FIPS 140-3 image after the cutover
FROM ghcr.io/aquia-inc/base-docker-images/fips-base:latest
```

To reference FIPS 140-3 explicitly (recommended for new work), use it by name:

```dockerfile
FROM ghcr.io/aquia-inc/base-docker-images/fips-140-3:latest
```

Either way the same compatibility differences apply, because the base image
changes from Alpine/musl to Wolfi/glibc:

| | `fips-base` (FIPS 140-2) | `fips-140-3` |
|---|---|---|
| Base image | `ghcr.io/wolfi-dev/alpine-base` | `cgr.dev/chainguard/wolfi-base` |
| C library | musl | **glibc** |
| Package manager | `apk` | `apk` |
| Default user | `nobody` (65534) | `nonroot` (65532) |
| FIPS root | `/usr/local/ssl` | `/opt/openssl-fips` (with `/usr/local/ssl` symlinks) |
| `openssl` on `PATH` | yes | yes |
| FIPS module | OpenSSL 3.0.9, cert #4282/#4811 | OpenSSL 3.1.2, cert #4985 |

What the base swap means in practice:

- **Package installs are unchanged.** Both images use Wolfi's `apk`, so any
  `apk add ...` layers in a consuming Dockerfile work the same way.
- **Rebuild native binaries - this is the breaking change.** A Go binary built
  with cgo, a Python/Node C extension, or any statically musl-linked artifact
  compiled on `fips-base` will not execute on glibc. Rebuild it on the new base.
  Pure-Go (`CGO_ENABLED=0`), interpreted code, and anything that only shells out
  to `openssl` are unaffected.
- **glibc is the more standard target.** musl's smaller libc has occasional
  behavioural differences (DNS resolver, locales, default thread stack size);
  moving to glibc removes those edge cases rather than introducing them.
- **Update UID assumptions.** Files owned by `nobody` (65534) and any Kubernetes
  `securityContext.runAsUser: 65534` must move to `nonroot` (65532).
- **OpenSSL usage needs no change.** `OPENSSL_CONF` and `OPENSSL_MODULES` are
  exported by both images, and the old `/usr/local/ssl` config paths are
  symlinked on `fips-140-3` (see below), so code that simply uses OpenSSL keeps
  working in approved mode.

### Legacy path shim in `fips-140-3`

`fips-140-3` keeps its FIPS material under `/opt/openssl-fips`, but the retired
`fips-base` used `/usr/local/ssl`. Those old paths are symlinked onto the real
ones, for a specific safety reason rather than convenience.

A missing `OPENSSL_CONF` is **not an error** in OpenSSL - it silently falls back
to the default provider. So a consumer migrating here who carried over
`OPENSSL_CONF=/usr/local/ssl/openssl.cnf` would have got an image that looked
FIPS-enabled and was not. Measured on the image before the shim existed:

```
OPENSSL_CONF=/usr/local/ssl/openssl.cnf openssl list -providers   ->  default
echo x | OPENSSL_CONF=/usr/local/ssl/openssl.cnf openssl dgst -md5 ->  SUCCEEDS
```

With the shim, the same commands yield `base, fips` and a refused MD5. A
build-time gate and container structure tests both assert this, so the shim
cannot silently rot.

**This is a convenience for a deliberate migration, not a claim of
equivalence.** Two differences no symlink can bridge, both of which fail loudly:

| | effect |
|---|---|
| musl to glibc | binaries built against `fips-base` will not execute |
| `nobody` (65534) to `nonroot` (65532) | file ownership and `runAsUser` mismatches |

Note also that the legacy path now resolves to **Module 3.1.2 under certificate
#4985**, not 3.0.9 under #4282/#4811. If your compliance position names a
specific certificate, the path being unchanged does not mean the certificate is.

### Compatibility shims in `fips-base`

Earlier revisions of `fips-base` shipped a source-built `openssl` binary at
`/usr/local/ssl/bin/openssl`. That binary is gone, because shipping the whole
3.0.9 tree is what could carry the out-of-boundary CVEs. The path is retained as a
symlink to the distribution binary, so consumers invoking it by absolute path
keep working and transparently get the patched, FIPS-enforcing OpenSSL.

The 3.0.9 shared libraries that used to sit under `/usr/local/ssl/lib64` are
**not** recreated. 
