FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY TRAFFIC_COLLECTOR.md .
COPY scripts ./scripts
COPY templates ./templates
COPY static ./static

ENV DATA_DIR=/data
EXPOSE 8001

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8001", "--access-logfile", "-", "app:app"]
