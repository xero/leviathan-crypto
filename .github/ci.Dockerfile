FROM oven/bun:debian AS bun
FROM mcr.microsoft.com/playwright:v1.58.2-noble

LABEL org.opencontainers.image.title="leviathan-crypto/ci"
LABEL org.opencontainers.image.description="cicd e2e testing toolchain for the leviathan-crypto library"
LABEL org.opencontainers.image.authors="https://github.com/xero/leviathan-crypto/graphs/contributors"
LABEL org.opencontainers.image.documentation="https://github.com/xero/leviathan-crypto/wiki"
LABEL org.opencontainers.image.url="https://github.com/xero/leviathan-crypto/actions"
LABEL org.opencontainers.image.source="https://github.com/xero/leviathan-crypto"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.created="2026-04-30"

# Pull the bun outta the oven
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN ln -s /usr/local/bin/bun /usr/local/bin/bunx
ENV PATH="/root/.bun/bin:${PATH}"

# Install dependencies
RUN apt-get update && apt-get install -y curl unzip

# Testing tools
RUN bun i -g playwright
RUN playwright install-deps && \
		playwright install && \
		playwright install chrome firefox webkit

# Set working directory
WORKDIR /app

# No CMD required for CI containers as all
# commands run are controlled by workflows
