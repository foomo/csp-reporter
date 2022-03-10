FROM --platform=linux/amd64 golang as builder

WORKDIR /go/server

COPY . .

RUN GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o /server ./main.go

FROM --platform=linux/amd64 alpine

COPY --from=builder /server /usr/bin/server

ENTRYPOINT ["/usr/bin/server"]