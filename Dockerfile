FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --create-home --uid 10001 svarog

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

COPY samples ./samples

USER svarog
ENTRYPOINT ["svarog"]
CMD ["--help"]
