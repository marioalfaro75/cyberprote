# Stage 1: Build
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /csf-collector ./cmd/collector/

# Stage 2: Final
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /csf-collector /csf-collector

EXPOSE 4317 4318 13133

ENTRYPOINT ["/csf-collector"]
