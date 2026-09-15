# Multi-stage Production Dockerfile for CodeSentinel AI
# Stage 1: Build stage
FROM node:22-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Install all dependencies including devDependencies
RUN npm ci

# Copy full application source
COPY . .

# Build client and server bundles
RUN npm run build

# Stage 2: Production runtime image
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Copy package manifests and production dependencies
COPY --from=builder /app/package*.json ./
RUN npm ci --omit=dev

# Copy compiled build output
COPY --from=builder /app/dist ./dist

# Non-root user for container security
USER node

EXPOSE 3000

# Launch compiled CommonJS server bundle
CMD ["node", "dist/server.cjs"]
