FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# COPYing the development `main.go` server
RUN CGO_ENABLED=0 go build -o /gin-auth ./cmd

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /gin-auth /gin-auth

EXPOSE 8080

ENTRYPOINT ["/gin-auth"]
