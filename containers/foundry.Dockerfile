# syntax=docker/dockerfile:1.6
# Pinned amd64 execution image. Apple Silicon uses Docker emulation so the exact
# same official solc binary runs on development Macs and Ubuntu experiment hosts.
FROM --platform=linux/amd64 ghcr.io/foundry-rs/foundry@sha256:2dbf3d0fc58593ad9d01ef57677f93f83f4987acd295d17f303448d82e3a3ae7

USER root
ADD --checksum=sha256:fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f \
    https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.24+commit.e11b9ed9 \
    /usr/local/bin/solc
RUN chmod 0555 /usr/local/bin/solc \
    && solc --version

USER foundry
WORKDIR /workspace

