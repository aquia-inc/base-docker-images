# End-of-life marker image, pushed over a retired tag by hand (see the
# "Retiring a frozen tag" runbook in FIPS.md). It is deliberately not named
# Dockerfile.* at the repository root, so no build workflow discovers it.
#
# The result is a scratch image holding one static binary, installed as both
# /bin/sh and the entrypoint. It prints the baked-in message and exits 1, so a
# consumer's RUN steps and `docker run` fail with the reason and the
# replacement image. It has no OS packages, so it scans clean.

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:08df5982c3d27e70a4ce1607e3bb9af09d746f8722cf135a7694afef879fc5a2 AS build

# hadolint ignore=DL3018
RUN apk add --no-cache build-base

COPY eol.c /src/eol.c
RUN gcc -static -Os -s -o /eol /src/eol.c

# RETIRED_REF is the retired image reference, REPLACEMENT_REF the image to use
# instead, PACKAGE_URL its package page, EOL_REASON one line of why.
ARG RETIRED_REF
ARG REPLACEMENT_REF
ARG ALTERNATIVE_REF
ARG PACKAGE_URL
ARG DOCS_URL
ARG EOL_REASON
RUN test -n "$RETIRED_REF" && test -n "$REPLACEMENT_REF" && test -n "$PACKAGE_URL" && \
    { \
      printf '\nERROR: %s has reached end of life and must not be used.\n\n' "$RETIRED_REF"; \
      printf '%s\n\n' "$EOL_REASON"; \
      printf 'Use this image instead:\n  %s\n' "$REPLACEMENT_REF"; \
      if [ -n "$ALTERNATIVE_REF" ]; then printf '  %s\n' "$ALTERNATIVE_REF"; fi; \
      printf '\nImage page:      %s\n' "$PACKAGE_URL"; \
      printf 'Migration notes: %s\n\n' "$DOCS_URL"; \
    } > /eol-message

FROM scratch
ARG RETIRED_REF
ARG REPLACEMENT_REF
COPY --from=build /eol /bin/sh
COPY --from=build /eol /eol
COPY --from=build /eol-message /etc/eol-message
LABEL org.aquia.base-docker-images.eol-marker="true" \
      org.opencontainers.image.title="End of life: ${RETIRED_REF}" \
      org.opencontainers.image.description="Retired. Use ${REPLACEMENT_REF} instead."
# Numeric, because scratch has no /etc/passwd. The binary and the message are
# world-readable, so nothing here needs root.
USER 65532:65532
ENTRYPOINT ["/eol"]
