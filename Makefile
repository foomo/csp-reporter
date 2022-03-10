TAG?=latest

.phony: build
build:
	docker build --platform linux/amd64 --push --progress=plain -t foomo/csp-reporter:$(TAG) -f docker/Dockerfile .

.phony: deploy
deploy:
	helm upgrade --install csp-reporter -f helm/overrides.yaml helm/csp-reporter