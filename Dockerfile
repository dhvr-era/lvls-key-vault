FROM node:22-alpine AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM node:22-alpine AS runtime

RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm install tsx

COPY --from=builder /app/dist ./dist
COPY server.ts tsconfig.json ./
COPY src ./src

EXPOSE 5000

CMD ["npx", "tsx", "server.ts"]
