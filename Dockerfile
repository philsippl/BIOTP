FROM python:3.12-slim

WORKDIR /app

COPY lib/biotp-py /app/lib/biotp-py
COPY server /app/server

RUN pip install --no-cache-dir /app/lib/biotp-py flask

WORKDIR /app/server
CMD ["python", "server.py"]
