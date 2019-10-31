# This Dockerfile is used by cross for cross-compilation and cross-testing of
# PARSEC.

FROM rustembedded/cross:aarch64-unknown-linux-gnu-0.1.16

RUN apt-get update && \
    # wget is needed in the build script to download the operations.
    apt-get install -y wget
