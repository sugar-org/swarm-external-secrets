FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vault-secrets-plugin .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/vault-secrets-plugin .

CMD ["./vault-secrets-plugin"]
