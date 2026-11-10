FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS builder

WORKDIR /go/csp-reporter

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /service ./cmd/reporter

FROM alpine:3.24.4

COPY --from=builder /service /usr/bin/service

EXPOSE 80 9200

CMD ["/usr/bin/service"]
