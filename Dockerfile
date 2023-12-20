# Use the specified Python version
FROM python:3.11.4-slim-buster as builder

# Configure Poetry
ENV POETRY_VERSION=1.6.1
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VENV=/opt/poetry-venv
ENV POETRY_CACHE_DIR=/opt/.cache

# Install poetry separated from system interpreter
RUN python3 -m venv $POETRY_VENV \
    && $POETRY_VENV/bin/pip install -U pip setuptools \
    && $POETRY_VENV/bin/pip install poetry==${POETRY_VERSION}

# Add `poetry` to PATH
ENV PATH="${PATH}:${POETRY_VENV}/bin"

# Set the working directory
WORKDIR /app

# Install dependencies
COPY poetry.lock pyproject.toml ./
RUN poetry install --no-root

# Copy the flask app to the working directory
COPY . /app

# Run the scripts
RUN poetry run python bin/updaterules.py
RUN poetry run python runner.py --convert snort
RUN poetry run python runner.py --convert et
RUN poetry run python runner.py --convert custom
# Uncomment the following line if you want to run conversion for suricata
# RUN poetry run python runner.py --convert suricata
RUN poetry run python bin/cvereport.py

# Build the site
WORKDIR /app/Magic-SigExplorer
RUN poetry run mkdocs build

# Use Nginx for serving
FROM nginx:alpine

# Copy static files to Nginx directory
COPY --from=builder /app/Magic-SigExplorer/site/ /usr/share/nginx/html

# Expose port for the application
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]