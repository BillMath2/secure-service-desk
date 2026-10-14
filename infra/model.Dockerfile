FROM ollama/ollama:0.40.3@sha256:adca95a12c2b386a8f9a995e7fa0600e187e3323b5e5522f5a6c3b1ec73eff99
USER 0:0
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables=1.0.9-1ubuntu0.1 util-linux=2.39.3-9ubuntu6.6 \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0555 scripts/model_bootstrap.sh /model-bootstrap.sh
ENTRYPOINT ["/model-bootstrap.sh"]
CMD []
