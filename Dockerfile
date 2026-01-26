# Use official Python runtime as a parent image
# Slim version for smaller footprint
FROM python:3.10-slim

# Set environment variables
# PYTHONDONTWRITEBYTECODE: Prevents Python from writing pyc files to disc
# PYTHONUNBUFFERED: Prevents Python from buffering stdout and stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Set work directory
WORKDIR /app

# Install system dependencies required for building python packages and Playwright
# nmap is included as a core tool
RUN apt-get update && apt-get install -y \
    gcc \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (Chromium only to save space)
RUN playwright install chromium
RUN playwright install-deps chromium

# Copy project files
COPY . .

# Create a non-root user for security (optional but recommended)
# However, Playwright sometimes has issues with root, relying on correct args.
# We'll run as root for simplicity in this pentest container, 
# ensuring the user passes --no-sandbox to chrome if needed.

# Expose any necessary ports (e.g. if we add a web server later)
# EXPOSE 8000

# Entrypoint
ENTRYPOINT ["python", "-m", "bugtrace"]
CMD ["--help"]
