# Build in CI only; production base must be independently reviewed and digest-pinned.
FROM node:22.16.0-bookworm-slim
WORKDIR /worker
COPY --chown=65532:65532 packages/worker/intelligence-local.mjs /worker/intelligence-local.mjs
USER 65532:65532
ENV NODE_ENV=production
ENTRYPOINT ["/usr/bin/timeout","--signal=KILL","5s","/usr/local/bin/node","--permission","--allow-fs-read=/worker/intelligence-local.mjs","--max-old-space-size=32","/worker/intelligence-local.mjs"]
