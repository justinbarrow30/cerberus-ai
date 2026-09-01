# CerberusAI — production image. Runs the operations console (which serves the
# setup wizard on first launch and self-starts the triage engine once configured).
FROM python:3.12-slim

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code.
COPY . .

# All mutable state lives on a mounted volume at /data (config, memory, verdicts),
# so a container restart never loses the learned network memory.
ENV CERBERUS_CONFIG=/data/config.json \
    CERBERUS_MEMORY_DB=/data/cerberus_memory.db \
    CERBERUS_VERDICTS=/data/verdicts.jsonl \
    CERBERUS_USERS_DB=/data/cerberus_users.db
RUN mkdir -p /data

EXPOSE 8787

# The dashboard serves the wizard + console and spawns the poller once configured.
CMD ["python", "-m", "uvicorn", "dashboard:app", "--host", "0.0.0.0", "--port", "8787"]
