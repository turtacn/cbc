# Stage 1: Build the Go application
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cbc-auth ./cmd/server

# Stage 2: Create the final image
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/cbc-auth .
COPY --from=builder /app/migrations ./migrations
EXPOSE 8080 50051
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:8080/health || exit 1
CMD ["./cbc-auth"]
#Personal.AI order the ending