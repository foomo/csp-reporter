TAG?=latest

.PHONY: run.reporter
run.reporter:
	go run ./cmd/reporter/main.go --address=:8080

.PHONY: run.example
run.example:
	go run ./example/server/main.go

.PHONY: test
test:
	go vet ./...
	go test -race ./...

.PHONY: build
build:
	docker build --progress=plain -t foomo/csp-reporter:$(TAG) -f ./Dockerfile .
