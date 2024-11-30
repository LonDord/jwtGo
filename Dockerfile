FROM golang:1.23.3 AS builder
WORKDIR /app
COPY go.* ./
COPY .env .env
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main main.go
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/main .
COPY --from=builder /app/.env .env
EXPOSE 3000
CMD ["./main"]