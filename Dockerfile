FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml ./
COPY jitca ./jitca
RUN pip install --no-cache-dir . && useradd --system --uid 10001 --create-home jitca && mkdir /state && chown jitca:jitca /state
COPY config.container.toml ./config.toml
USER jitca
EXPOSE 15353/udp 18443/tcp
ENTRYPOINT ["jitca", "--config", "/app/config.toml", "serve"]
