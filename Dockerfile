# Stage 1: Base image
FROM python:3.10-slim as base
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: App
FROM base
WORKDIR /app
COPY . /app
ENV PYTHONPATH=/app
CMD ["python", "webtest.py"]
