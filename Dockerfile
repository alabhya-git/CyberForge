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
COPY scripts/serve_all.py ./scripts/serve_all.py
COPY --from=web /app/web/dist ./web/dist/
# UID 1000 matches Hugging Face Spaces; Compose and other hosts accept it too.
RUN useradd --create-home --uid 1000 twokey && mkdir /runtime && chown twokey:twokey /runtime
USER twokey
ENV TWOKEY_RUNTIME_DIR=/runtime PORT=7860
EXPOSE 7860
# Default: the whole lab in one container behind the demo password (scripts/serve_all.py).
# compose.yaml overrides the command to run each service in its own container.
CMD ["python", "scripts/serve_all.py"]
