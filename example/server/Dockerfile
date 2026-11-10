FROM golang:1.27.3-alpine AS builder

WORKDIR /go/server

COPY . .

RUN CGO_ENABLED=0 go build -o /server ./main.go

FROM alpine:3.24.4

COPY --from=builder /server /usr/bin/server

ENTRYPOINT ["/usr/bin/server"]
