# Read-only dashboard + replay runner. No scanner binaries and no credentials live here.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY hardening_loop ./hardening_loop
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 app
COPY --from=build /install /usr/local
WORKDIR /app
# Committed evidence needed offline by replay (R0) and the upstream-master comparison report.
COPY fixtures ./fixtures
ENV HL_DATA_DIR=/data \
    HL_REPO_ROOT=/app \
    HL_DASHBOARD_HOST=0.0.0.0 \
    HL_DASHBOARD_PORT=8080 \
    PYTHONUNBUFFERED=1
RUN mkdir -p /data && chown app:app /data
USER app
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"
ENTRYPOINT ["hardening-loop"]
CMD ["serve"]
