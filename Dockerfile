FROM python:3.13-slim
# bash/openssl/ripgrep are needed by scripts/discover-issuers.sh
RUN apt-get update && apt-get install -y --no-install-recommends bash openssl ripgrep \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml ./
COPY jitca ./jitca
RUN pip install --no-cache-dir . && useradd --system --uid 10001 --create-home jitca && mkdir /state && chown jitca:jitca /state
COPY scripts/discover-issuers.sh ./scripts/discover-issuers.sh
COPY docker ./docker
RUN chmod 0755 scripts/discover-issuers.sh docker/entrypoint.sh
USER jitca
EXPOSE 15353/udp 18443/tcp
ENTRYPOINT ["/app/docker/entrypoint.sh"]
