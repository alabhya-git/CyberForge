FROM node:24-alpine AS web
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.13-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY twokey/ ./twokey/
COPY --from=web /app/web/dist ./web/dist/
RUN useradd --system --user-group twokey && mkdir /runtime && chown twokey:twokey /runtime
USER twokey
ENV TWOKEY_RUNTIME_DIR=/runtime
CMD ["python", "-m", "uvicorn", "twokey.control:app", "--host", "0.0.0.0", "--port", "8100"]
