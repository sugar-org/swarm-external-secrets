FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o swarm-external-secrets .

FROM alpine:3.21.3

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/swarm-external-secrets .

CMD ["./swarm-external-secrets"]