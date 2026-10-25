
# syntax=docker/dockerfile:1
FROM python:3.12-slim

ARG PIP_INDEX_URL=https://pypi.org/simple

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml ./
COPY alembic.ini ./
COPY migrations ./migrations
COPY src ./src
COPY scripts ./scripts

RUN pip install --no-cache-dir --index-url="${PIP_INDEX_URL}" --timeout=60 --retries=10 .

EXPOSE 8000

CMD ["uvicorn", "src.api.rest.app:app", "--host", "0.0.0.0", "--port", "8000"]
