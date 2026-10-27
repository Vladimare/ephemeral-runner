FROM ubuntu:24.04

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git python3 \
    libicu74 libssl3t64 libkrb5-3 zlib1g liblttng-ust1t64 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /bin/bash runner \
    && install -d -o runner -g runner /home/runner/actions-runner

ARG RUNNER_VERSION=2.338.0
# Pinned SHA256 for the official actions/runner linux-x64 v2.338.0 archive.
ARG RUNNER_SHA256=af4b794c1bc41d73d40535e3fe092a39f9679cd8d965954c2aca25a05ca41d32
USER runner
ENV HOME=/home/runner
WORKDIR /home/runner/actions-runner
RUN curl -fsSL --retry 3 \
      "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
      -o /tmp/runner.tar.gz \
    && echo "${RUNNER_SHA256}  /tmp/runner.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/runner.tar.gz \
    && rm /tmp/runner.tar.gz

# The host launcher supplies a read-only entrypoint script. This image is a
# minimal example; build an extended one for Rust, Skia, C/C++, etc.
CMD ["/bin/bash"]
