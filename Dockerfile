# much smaller image than debian based python images
FROM python:3.14-slim

LABEL maintainer="rasty94"

WORKDIR /app

# Install git and clean up apt cache to minimize image size
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Download Astral's uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# copy requirements.txt for better caching 
COPY requirements.txt .

# Install py dependencies using uv for near-instant installation
RUN uv pip install --system --no-cache -r requirements.txt

# Copy all code at once  instead of copy code then files 
COPY . .

# Expose Streamlit default port
EXPOSE 8501

# Use CMD instead of ENTRYPOINT to easily allow overriding to launch Streamlit
CMD ["python", "start.py"]
