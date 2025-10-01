FROM ghcr.io/owasp-noir/noir:latest AS noir

FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r reconagent && useradd -r -g reconagent -m -d /home/reconagent reconagent

WORKDIR /build

RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_checksums.txt && \
    wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    grep "nuclei_3.3.7_linux_amd64.zip" nuclei_3.3.7_checksums.txt | sha256sum -c - && \
    unzip -q nuclei_3.3.7_linux_amd64.zip && \
    chmod +x nuclei && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_3.3.7_checksums.txt nuclei_3.3.7_linux_amd64.zip

RUN mkdir -p /home/reconagent && chown -R reconagent:reconagent /home/reconagent
USER reconagent
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /home/reconagent/nuclei-templates
USER root

FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN groupadd -r reconagent && useradd -r -g reconagent -m -d /home/reconagent reconagent

RUN python -m pip install --upgrade pip pipx

ENV PATH="/home/reconagent/.local/bin:${PATH}"

RUN mkdir -p /home/reconagent/.local && chown -R reconagent:reconagent /home/reconagent
USER reconagent
RUN pipx install uro
USER root

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir waymore uddup

COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei

COPY --from=noir /usr/local/bin/noir /usr/local/bin/noir

COPY --from=builder --chown=reconagent:reconagent /home/reconagent/nuclei-templates /home/reconagent/nuclei-templates

ENV PLAYWRIGHT_BROWSERS_PATH=/home/reconagent/.cache/ms-playwright
RUN mkdir -p /home/reconagent/.cache && chown -R reconagent:reconagent /home/reconagent/.cache
RUN su - reconagent -c "playwright install chromium"
RUN playwright install-deps

COPY --chown=reconagent:reconagent . .

RUN mkdir -p /app/results && chmod 755 /app/results

ENV PYTHONUNBUFFERED=1

USER reconagent

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import crewai; import sys; sys.exit(0)"

ENTRYPOINT ["python", "reconagent.py"]
CMD ["--help"]