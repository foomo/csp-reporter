TAG?=latest

.phony: run.reporter
run.reporter:
	go run ./cmd/reporter/main.go --address=:8080

.phony: run.example
run.example:
	go run ./example/server/main.go

.phony: build
build:
	docker build --platform linux/amd64 --push --progress=plain -t foomo/csp-reporter:$(TAG) -f docker/Dockerfile .

.phony: deploy
deploy:
	helm upgrade --install csp-reporter -f helm/overrides.yaml helm/csp-reporter