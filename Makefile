EJBCA_DIR := test/integration/ejbca

.PHONY: test setup teardown integration integration-ejbca integration-openssl help

test: ## Run unit tests
	go test -v ./...

# -- Integration test environment --

setup: ## Start and configure EJBCA environment
	docker compose -f $(EJBCA_DIR)/docker-compose.yml up -d
	bash $(EJBCA_DIR)/setup.sh

teardown: ## Stop and remove EJBCA environment
	docker compose -f $(EJBCA_DIR)/docker-compose.yml down

# -- Integration tests --

integration: ## Run all integration tests
	go test -v -tags integration ./test/integration/...

integration-ejbca: ## Run EJBCA tests
	go test -v -tags integration ./test/integration/ejbca

integration-openssl: ## Run OpenSSL tests
	go test -v -tags integration ./test/integration/openssl

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
