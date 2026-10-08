# One build for the three robots. Build context: the repository root.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY impl/go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/ ./cmd/writ ./cmd/writ-agent ./cmd/writ-openclaw

# A and C: the writ CLI and the payment agent, nothing else.
FROM debian:bookworm-slim AS tools
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/* && useradd -m -u 1000 agent
COPY --from=build /out/ /usr/local/bin/
USER agent
WORKDIR /home/agent

# B: OpenClaw, pinned, plus the adapter that gives it a Writ-bounded payment tool.
FROM node:24-slim AS openclaw
RUN npm install -g openclaw@2026.9.9 && npm cache clean --force
COPY --from=build /out/writ-openclaw /usr/local/bin/
USER node
WORKDIR /home/node
