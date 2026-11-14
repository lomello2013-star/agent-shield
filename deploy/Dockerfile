FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STML_TENANT=default \
    STML_DB=/data/stml.sqlite3 \
    STML_TRUST_DIR=/data/trust

WORKDIR /app
COPY stml /app/stml
RUN pip install --no-cache-dir "pydantic>=2.7,<3" "cryptography>=42,<51"

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3)"

CMD ["python", "-m", "stml.server", "run", "--host", "0.0.0.0", "--port", "8080", "--db", "/data/stml.sqlite3", "--trust-dir", "/data/trust"]
