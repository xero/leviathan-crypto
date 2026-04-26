FROM oven/bun:debian AS bun
FROM mcr.microsoft.com/playwright:latest

LABEL org.opencontainers.image.title="leviathan-crypto/ci"
LABEL org.opencontainers.image.description="cicd e2e testing toolchain for the leviathan-crypto library"
LABEL org.opencontainers.image.authors="https://github.com/xero/leviathan-crypto/graphs/contributors"
LABEL org.opencontainers.image.documentation="https://github.com/xero/leviathan-crypto/wiki"
LABEL org.opencontainers.image.url="https://github.com/xero/leviathan-crypto/actions"
LABEL org.opencontainers.image.source="https://github.com/xero/leviathan-crypto"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.created="2026-04-25"

# Pull the bun outta the oven
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
ENV PATH="/root/.bun/bin:${PATH}"

# Install dependencies
RUN apt-get update && apt-get install -y curl unzip

# Testing tools
RUN bun i -g playwright eslint

# Playwright browsers — uses Playwright's bundled chromium/firefox/webkit
# (no system Chrome). leviathan-crypto's playwright.config.ts selects
# projects by browserName, not channel, so the bundled binaries are
# what the e2e suite actually exercises.
RUN playwright install-deps && \
		playwright install

# Set working directory
WORKDIR /app

# No CMD required for CI containers as all
# commands run are controlled by workflows
