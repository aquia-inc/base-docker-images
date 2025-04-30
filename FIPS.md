# FIPS Base Image Summary

This Docker image provides a base environment built upon Wolfi's Alpine-based image (`ghcr.io/wolfi-dev/alpine-base`), chosen for its minimal footprint and suitable build tooling. The primary feature is a custom-compiled version of OpenSSL 3.0.9 with FIPS support enabled and activated.

**OpenSSL & FIPS:** OpenSSL is a core library for TLS/SSL and cryptographic functions. This image uses version 3.0.9, compiled specifically to enable its **FIPS 140-2/3 validated cryptographic module**. Compliance with FIPS is often mandated for US government systems and regulated industries.

## Key Functionality

*   **FIPS-Enabled OpenSSL Build:** OpenSSL 3.0.9 is compiled from source with the `enable-fips` configuration flag. The FIPS module (`fips.so`) is installed, and the necessary FIPS configuration (`/usr/local/ssl/fipsmodule.cnf`) is generated via `openssl fipsinstall`.
*   **Default FIPS Activation:** The primary OpenSSL configuration (`/usr/local/ssl/openssl.cnf`) is structured to automatically load the FIPS provider configuration and set `activate = 1` within the `fips_sect`. This ensures FIPS mode is active by default for applications using this configuration.
*   **Custom Installation Path:** OpenSSL is installed in `/usr/local/ssl` to avoid conflicts with potential system-provided versions and ensure clarity.
*   **PATH Prioritization:** The `/usr/local/ssl/bin` directory is prepended to the container's `PATH` environment variable, ensuring that the custom `openssl` binary is invoked by default.
*   **Build Environment Abstraction:** Provides a ready-to-use FIPS environment, abstracting the complexities of the OpenSSL FIPS build and configuration process.
*   **Secure Foundation:**
    *   Leverages a minimal Wolfi base image to reduce attack surface.
    *   Sets the default user to `nobody` (UID 65534) as a security best practice, minimizing privileges.
*   **Optimized Image Size:** Build dependencies and source artifacts are removed post-installation to minimize the final image layer size.

**Use Case:** This image serves as a foundation for building and deploying applications requiring FIPS 140-2/3 validated cryptography through OpenSSL, particularly where government or regulatory compliance is necessary. It simplifies the setup by providing a pre-configured FIPS environment.
