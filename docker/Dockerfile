FROM golang as base

WORKDIR /go/csp-reporter

COPY ./go.mod ./go.sum ./

RUN  go mod download -x

COPY . .

FROM base as builder

RUN GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o /service ./cmd/reporter/main.go

FROM alpine

COPY --from=builder /service /usr/bin/service

CMD "/usr/bin/service"