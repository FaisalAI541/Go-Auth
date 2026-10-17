
# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy the complete project, including go.mod and source files
COPY . .

# Resolve dependencies after source files are available
RUN go mod tidy

# Download dependencies and verify checksums
RUN go mod download

# Compile the auth service
RUN CGO_ENABLED=0 GOOS=linux \
    go build -mod=mod -ldflags="-w -s" \
    -o /bin/auth-service ./cmd/server

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -g "" appuser

COPY --from=builder /bin/auth-service /bin/auth-service

USER appuser

EXPOSE 8080

ENTRYPOINT ["/bin/auth-service"]
