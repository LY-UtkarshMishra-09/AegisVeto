# Stage 1: Build Frontend Dashboard
FROM node:20-alpine AS dashboard-builder
WORKDIR /app/dashboard
COPY dashboard/package*.json ./
RUN npm ci
COPY dashboard/ ./
RUN npm run build

# Stage 2: Build Core Backend
FROM node:20-alpine AS core-builder
RUN apk add --no-cache python3 make g++
WORKDIR /app/core
COPY core/package*.json ./
RUN npm ci
COPY core/ ./
RUN npm run build

# Stage 3: Production Runtime
FROM node:20-alpine AS runner
RUN apk add --no-cache python3 make g++
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Install production dependencies for core
COPY core/package*.json ./core/
RUN cd core && npm ci --omit=dev

# Copy compiled backend dist and frontend dist
COPY --from=core-builder /app/core/dist ./core/dist
COPY --from=dashboard-builder /app/dashboard/dist ./dashboard/dist

# Copy baseline configuration, policy, and sandbox target
COPY policy.yaml ./policy.yaml
COPY sandbox ./sandbox

EXPOSE 3000

# Volume mount points for persistent SQLite audit database and root policy
VOLUME ["/app/aegisveto_audit.db", "/app/policy.yaml"]

CMD ["node", "core/dist/index.js"]
