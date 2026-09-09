FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY relay.py /relay.py

USER nobody
EXPOSE 8080

CMD ["python3", "-u", "/relay.py"]
