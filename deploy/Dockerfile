FROM node:20-alpine AS interface
WORKDIR /build
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY dashboard/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt requirements-production.txt ./
RUN pip install -r requirements.txt -r requirements-production.txt
COPY raqeeb/ raqeeb/
COPY reference/ reference/
COPY observatory/ observatory/
COPY pyproject.toml ./
COPY --from=interface /build/dist dashboard/dist
COPY deploy/start.sh /usr/local/bin/start-raqeeb
RUN useradd --system --uid 10001 --home /app raqeeb \
    && mkdir -p /app/evidence && chown -R raqeeb /app/evidence \
    && chmod 0755 /usr/local/bin/start-raqeeb
USER raqeeb
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request as u; u.urlopen(u.Request('http://127.0.0.1:8000/api/health', headers={'X-Forwarded-Proto': 'https'}), timeout=4)"
CMD ["start-raqeeb"]
