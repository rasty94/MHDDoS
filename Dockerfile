FROM python:3.14-alpine

LABEL maintainer="rasty94"

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache \
    git \
    nmap \
    ruby \
    ruby-bigdecimal \
    libffi \
    libxml2 \
    libxslt \
    curl \
    zlib

# Install build dependencies, build and install WPScan, then remove build dependencies
RUN apk add --no-cache --virtual .build-deps \
    build-base \
    ruby-dev \
    libffi-dev \
    libxml2-dev \
    libxslt-dev \
    curl-dev \
    zlib-dev \
    && gem install wpscan --no-document \
    && apk del .build-deps

# Download Astral's uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# copy dependency manifest first for better layer caching
COPY pyproject.toml .

# Install py dependencies using uv for near-instant installation
RUN uv pip install --system --no-cache -r pyproject.toml

# Copy all code at once  instead of copy code then files 
COPY . .

# Expose Streamlit default port
EXPOSE 8501

# Use CMD instead of ENTRYPOINT to easily allow overriding to launch Streamlit
CMD ["python", "start.py"]
