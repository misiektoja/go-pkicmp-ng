CMP_TEST_SUITE_DIR := test/integration/cmp-test-suite/testdata/cmp-test-suite
CMP_TEST_SUITE_COMMIT := d35c9de4516924b0a9a96176b3c8692660e57a8c

.PHONY: test test-integration test-integration-ejbca test-integration-openssl test-integration-cmp-test-suite \
        setup setup-ejbca setup-cmp-test-suite teardown teardown-ejbca clean help

# Testing

test: ## Run unit tests
	go test -v ./...

test-integration: test-integration-ejbca test-integration-openssl test-integration-cmp-test-suite ## Run all integration tests

test-integration-ejbca: ## Run EJBCA integration tests
	go test -v -tags integration ./test/integration/ejbca

test-integration-openssl: ## Run OpenSSL integration tests
	go test -v -tags integration ./test/integration/openssl

test-integration-cmp-test-suite: ## Run CMP test suite integration tests
	go test -v -tags integration -timeout 15m ./test/integration/cmp-test-suite

# Setup and teardown

setup: setup-ejbca setup-cmp-test-suite ## Setup all environments

setup-ejbca: ## Start and configure EJBCA environment
	docker compose -f test/integration/ejbca/docker-compose.yml up -d
	bash test/integration/ejbca/setup.sh

setup-cmp-test-suite: _clone-cmp-test-suite _sync-cmp-test-suite ## Clone and setup cmp-test-suite

teardown: teardown-ejbca ## Teardown all environments

teardown-ejbca: ## Stop and remove EJBCA environment
	docker compose -f test/integration/ejbca/docker-compose.yml down

clean: ## Remove generated artifacts
	rm -rf $(CMP_TEST_SUITE_DIR)

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Internal targets

_clone-cmp-test-suite:
	@if [ ! -d "$(CMP_TEST_SUITE_DIR)" ]; then \
		git clone --depth 1 https://github.com/siemens/cmp-test-suite.git $(CMP_TEST_SUITE_DIR) && \
		cd $(CMP_TEST_SUITE_DIR) && git fetch --depth 1 origin $(CMP_TEST_SUITE_COMMIT) && git checkout $(CMP_TEST_SUITE_COMMIT); \
	fi

_sync-cmp-test-suite:
	cd $(CMP_TEST_SUITE_DIR) && uv sync --extra pq
