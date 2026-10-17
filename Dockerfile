# Obscura demo-ui — single container: Node/Express server + baked-in NER model.
FROM node:24-slim

# onnxruntime-node (pulled in by @xenova/transformers) needs libgomp at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first for better layer caching. The workspace package.json files
# must be present so npm can wire up the @obscura/* workspace symlinks.
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/package.json
COPY packages/sdk/package.json packages/sdk/package.json
COPY apps/demo-ui/package.json apps/demo-ui/package.json
RUN npm ci

# Build all workspaces (core -> sdk -> demo-ui).
COPY . .
RUN npm run build

# Bake the NER model into the image. Tolerant of build-time network failure:
# the server lazily downloads the model on first boot if this is skipped.
RUN node scripts/warmup.mjs || echo "warmup skipped; model will download on first boot"

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

# __dirname-based paths in server.ts resolve absolutely, but the model cache is
# relative to CWD — keep it /app so the baked cache is found at runtime.
CMD ["node", "apps/demo-ui/dist/server.js"]
