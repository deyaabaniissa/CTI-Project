FROM node:22-alpine AS frontend

WORKDIR /build/cti-dashboard
COPY cti-dashboard/package.json cti-dashboard/package-lock.json ./
RUN npm ci
COPY cti-dashboard/ ./
RUN npm run build


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=8000

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./
COPY --from=frontend /build/cti-dashboard/dist ./cti-dashboard/dist

EXPOSE 8000

CMD ["sh", "-c", "python -m alembic upgrade head && gunicorn --bind 0.0.0.0:${PORT:-8000} --worker-class gthread --threads 8 --timeout 180 flask_app:app"]
