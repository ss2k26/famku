# famku: Go API + Svelte 5 SPA. Build context = this folder (backend/ and frontend/ side by side).
#   platform:  bin/platform build-app famku
#   registry:  docker build -t ghcr.io/org/famku:1.0.0 . && docker push ...   (then APP_IMAGE=... in the stack .env)
ARG GO_VERSION=1.27

# --- 1) frontend: vite writes straight into the Go embed folder (see frontend/vite.config.ts)
FROM node:22-alpine AS web
WORKDIR /src/frontend
COPY frontend/package*.json ./
# npm ci when a lockfile is committed (recommended), npm install otherwise
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ ./
ARG VITE_API_URL=
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# --- 2) backend
FROM golang:${GO_VERSION}-alpine AS gobuild
WORKDIR /src/backend
COPY backend/ ./
COPY --from=web /src/backend/internal/infrastructure/webui/dist ./internal/infrastructure/webui/dist
# go.sum is created on first build if missing; commit it afterwards for reproducible builds
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# --- 3) runtime: static binary, CA certs + tzdata, non-root
FROM gcr.io/distroless/static:nonroot
COPY --from=gobuild /out/server /server
EXPOSE 8080
ENTRYPOINT ["/server"]
