# WITNESS frontend container — Next.js 16.
# Cross-platform: same image runs on Linux, macOS, Windows.
# Build: docker build -t witness-frontend -f docker/frontend.Dockerfile .

FROM node:22-slim

# Install bun for faster installs (matches the dev workflow).
RUN npm install -g bun

WORKDIR /app

# Copy package files first for layer caching
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile || bun install

# Copy the rest
COPY . .

# Build (Next.js 16 standalone output)
ENV NEXT_TELEMETRY_DISABLED=1
# A failed build must fail the image.
RUN bun run build

EXPOSE 3000
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

CMD ["bun", "run", "start"]
