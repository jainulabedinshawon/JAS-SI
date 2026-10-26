FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# Create a dedicated, unprivileged runtime user.
RUN groupadd --system --gid 10001 jas-si \
    && useradd --system \
       --uid 10001 \
       --gid jas-si \
       --home-dir /app \
       --no-create-home \
       --shell /usr/sbin/nologin \
       jas-si

# Install exact, hash-verified dependencies from lock file.
COPY requirements.lock.txt /app/requirements.lock.txt
RUN python -m pip install \
    --no-cache-dir \
    --require-hashes \
    -r /app/requirements.lock.txt

# Copy only application source into the runtime image.
COPY src/ /app/src/

USER 10001:10001

EXPOSE 8000

# Liveness check only; does not claim the API is enabled.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).read()" || exit 1

CMD ["uvicorn", "jas_si_agent.api:app", "--host", "0.0.0.0", "--port", "8000"]
