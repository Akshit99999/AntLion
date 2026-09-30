FROM python:3.11-slim

LABEL maintainer="Akshit Sharma <akshitsharma684@gmail.com>"
LABEL description="Antlion — honeypot intrusion detection system"

# System packages needed for raw sockets / tcpdump in the capture layer
RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpdump \
        libpcap-dev \
        net-tools \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the dependency manifest first so Docker can cache this layer
COPY pyproject.toml ./

# Install the package in editable mode (resolves deps from pyproject.toml)
# We copy the full source afterwards so edits don't bust the dep-cache layer
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
        fastapi \
        uvicorn[standard] \
        scikit-learn \
        pandas \
        numpy \
        joblib \
        httpx \
        pytest

COPY . .

RUN pip install --no-cache-dir -e .

# Persistent volume for the SQLite database and model artifacts
VOLUME ["/root/.antlion"]

# Default exposed ports:
#   8000  — REST API + SOC Dashboard
#   8080  — Web decoy (InfraOps honeypot)
#   2222  — SSH/Telnet decoy
EXPOSE 8000 8080 2222

# Default command: print usage; override via docker run or docker-compose
CMD ["antlion", "--help"]
