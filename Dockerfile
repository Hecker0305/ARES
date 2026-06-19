FROM golang:1.26-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/ares ./cmd/ares

FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl chromium-browser

COPY --from=builder /usr/local/bin/ares /usr/local/bin/ares

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s \
  CMD curl -sf http://localhost:8080/health || exit 1

ENTRYPOINT ["ares"]
CMD ["serve", "--port", "8080"]
