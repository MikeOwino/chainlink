.DEFAULT_GOAL := chainlink

COMMIT_SHA ?= $(shell git rev-parse HEAD)
VERSION = $(shell jq -r '.version' package.json)
GO_LDFLAGS := $(shell tools/bin/ldflags)
GOFLAGS = -ldflags "$(GO_LDFLAGS)"
GCFLAGS = -gcflags "$(GO_GCFLAGS)"

.PHONY: install
install: install-chainlink-autoinstall ## Install chainlink and all its dependencies.

.PHONY: install-git-hooks
install-git-hooks: ## Install git hooks.
	git config core.hooksPath .githooks

.PHONY: install-chainlink-autoinstall
install-chainlink-autoinstall: | pnpmdep gomod install-chainlink ## Autoinstall chainlink.

.PHONY: pnpmdep
pnpmdep: ## Install solidity contract dependencies through pnpm
	(cd contracts && pnpm i)

.PHONY: gomod
gomod: ## Ensure chainlink's go dependencies are installed.
	@if [ -z "`which gencodec`" ]; then \
		go install github.com/smartcontractkit/gencodec@latest; \
	fi || true
	go mod download

.PHONY: gomodtidy
gomodtidy: gomods ## Run go mod tidy on all modules.
	gomods tidy

.PHONY: docs
docs: ## Install and run pkgsite to view Go docs
	go install golang.org/x/pkgsite/cmd/pkgsite@latest
	# http://localhost:8080/pkg/github.com/smartcontractkit/chainlink/v2/
	pkgsite

.PHONY: install-chainlink
install-chainlink: operator-ui ## Install the chainlink binary.
	go install $(GCFLAGS) $(GOFLAGS) .

.PHONY: install-chainlink-cover
install-chainlink-cover: operator-ui ## Install the chainlink binary with cover flag.
	go install -cover $(GOFLAGS) .

.PHONY: chainlink
chainlink: ## Build the chainlink binary.
	go build $(GOFLAGS) .

.PHONY: chainlink-dev
chainlink-dev: ## Build a dev build of chainlink binary.
	go build -tags dev $(GOFLAGS) .

.PHONY: chainlink-test
chainlink-test: ## Build a test build of chainlink binary.
	go build $(GOFLAGS) .

.PHONY: install-medianpoc
install-medianpoc: ## Build & install the chainlink-medianpoc binary.
	go install $(GOFLAGS) ./plugins/cmd/chainlink-medianpoc

.PHONY: install-ocr3-capability
install-ocr3-capability: ## Build & install the chainlink-ocr3-capability binary.
	go install $(GOFLAGS) ./plugins/cmd/chainlink-ocr3-capability

.PHONY: install-plugins
install-plugins: ## Build & install LOOPP binaries for products and chains.
	cd $(shell go list -m -f "{{.Dir}}" github.com/smartcontractkit/chainlink-feeds) && \
	go install $(GOFLAGS) ./cmd/chainlink-feeds
	cd $(shell go list -m -f "{{.Dir}}" github.com/smartcontractkit/chainlink-data-streams) && \
	go install $(GOFLAGS) ./mercury/cmd/chainlink-mercury
	cd $(shell go mod download -json github.com/smartcontractkit/chainlink-cosmos@f740e9ae54e79762991bdaf8ad6b50363261c056 | jq -r .Dir) && \
	go install $(GOFLAGS) ./pkg/cosmos/cmd/chainlink-cosmos
	cd $(shell go list -m -f "{{.Dir}}" github.com/smartcontractkit/chainlink-solana) && \
	go install $(GOFLAGS) ./pkg/solana/cmd/chainlink-solana
	cd $(shell go mod download -json github.com/smartcontractkit/chainlink-starknet/relayer@9a780650af4708e4bd9b75495feff2c5b4054e46 | jq -r .Dir) && \
	go install $(GOFLAGS) ./pkg/chainlink/cmd/chainlink-starknet

.PHONY: docker ## Build the chainlink docker image
docker:
	docker buildx build \
	--build-arg COMMIT_SHA=$(COMMIT_SHA) \
	-f core/chainlink.Dockerfile .

.PHONY: docker-ccip ## Build the chainlink docker image
docker-ccip:
	docker buildx build \
	--build-arg COMMIT_SHA=$(COMMIT_SHA) \
	-f core/chainlink.Dockerfile . -t chainlink-ccip:latest

	docker buildx build \
	--build-arg COMMIT_SHA=$(COMMIT_SHA) \
	-f ccip/ccip.Dockerfile .

.PHONY: docker-plugins ## Build the chainlink-plugins docker image
docker-plugins:
	docker buildx build \
	--build-arg COMMIT_SHA=$(COMMIT_SHA) \
	-f plugins/chainlink.Dockerfile .

.PHONY: operator-ui
operator-ui: ## Fetch the frontend
	go run operator_ui/install.go .

.PHONY: abigen
abigen: ## Build & install abigen.
	./tools/bin/build_abigen

.PHONY: generate
generate: abigen codecgen mockery protoc gomods ## Execute all go:generate commands.
	## Updating PATH makes sure that go:generate uses the version of protoc installed by the protoc make command.
	export PATH="$(HOME)/.local/bin:$(PATH)"; gomods -w go generate -x ./...
	find . -type f -name .mockery.yaml -execdir mockery \; ## Execute mockery for all .mockery.yaml files

.PHONY: rm-mocked
rm-mocked:
	grep -rl "^// Code generated by mockery" | grep .go$ | xargs -r rm

.PHONY: testscripts
testscripts: chainlink-test ## Install and run testscript against testdata/scripts/* files.
	go install github.com/rogpeppe/go-internal/cmd/testscript@latest
	go run ./tools/txtar/cmd/lstxtardirs -recurse=true | PATH="$(CURDIR):${PATH}" xargs -I % \
		sh -c 'testscript -e COMMIT_SHA=$(COMMIT_SHA) -e HOME="$(TMPDIR)/home" -e VERSION=$(VERSION) $(TS_FLAGS) %/*.txtar'

.PHONY: testscripts-update
testscripts-update: ## Update testdata/scripts/* files via testscript.
	make testscripts TS_FLAGS="-u"

.PHONY: start-testdb
start-testdb:
	docker run --name test-db-core -p 5432:5432 -e POSTGRES_PASSWORD=postgres -d postgres

.PHONY: setup-testdb
setup-testdb: ## Setup the test database.
	./core/scripts/setup_testdb.sh

.PHONY: testdb
testdb: ## Prepares the test database.
	go run . local db preparetest

.PHONY: testdb-force
testdb-force: ## Prepares the test database, drops any pesky user connections that stand in the the way.
	go run . local db preparetest --force

.PHONY: testdb-user-only
testdb-user-only: ## Prepares the test database with user only.
	go run . local db preparetest --user-only

.PHONY: gomods
gomods: ## Install gomods
	go install github.com/jmank88/gomods@v0.1.5

.PHONY: gomodslocalupdate
gomodslocalupdate: gomods ## Run gomod-local-update
	go install ./tools/gomod-local-update/cmd/gomod-local-update
	gomods -w gomod-local-update
	gomods tidy

.PHONY: mockery
mockery: $(mockery) ## Install mockery.
	go install github.com/vektra/mockery/v2@v2.50.0

.PHONY: codecgen
codecgen: $(codecgen) ## Install codecgen
	go install github.com/ugorji/go/codec/codecgen@v1.2.10

.PHONY: protoc
protoc: ## Install protoc
	core/scripts/install-protoc.sh 29.3 /
	go install google.golang.org/protobuf/cmd/protoc-gen-go@`go list -m -json google.golang.org/protobuf | jq -r .Version`
	go install github.com/smartcontractkit/wsrpc/cmd/protoc-gen-go-wsrpc@`go list -m -json github.com/smartcontractkit/wsrpc | jq -r .Version`

.PHONY: telemetry-protobuf
telemetry-protobuf: $(telemetry-protobuf) ## Generate telemetry protocol buffers.
	protoc \
	--go_out=. \
	--go_opt=paths=source_relative \
	--go-wsrpc_out=. \
	--go-wsrpc_opt=paths=source_relative \
	./core/services/synchronization/telem/*.proto

.PHONY: config-docs
config-docs: ## Generate core node configuration documentation
	go run ./core/config/docs/cmd/generate -o ./docs/

.PHONY: golangci-lint
golangci-lint: ## Run golangci-lint for all issues.
	[ -d "./golangci-lint" ] || mkdir ./golangci-lint && \
	docker run --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v1.62.2 golangci-lint run --max-issues-per-linter 0 --max-same-issues 0 | tee ./golangci-lint/$(shell date +%Y-%m-%d_%H:%M:%S).txt

.PHONY: modgraph
modgraph:
	go install github.com/jmank88/modgraph@v0.1.0
	./tools/bin/modgraph > go.md

.PHONY: test-short
test-short: ## Run 'go test -short' and suppress uninteresting output
	go test -short ./... | grep -v "\[no test files\]" | grep -v "\(cached\)"

.PHONY: run_flakeguard_validate_tests
run_flakeguard_validate_tests:
	@read -p "Enter a comma-separated list of test packages (e.g., package1,package2): " PKGS; \
	 read -p "Enter the number of times to rerun the tests (e.g., 5): " REPS; \
	 read -p "Enter the test runner (default: ubuntu-20.04): " RUNNER; \
	 RUNNER=$${RUNNER:-ubuntu-20.04}; \
	 gh workflow run flakeguard-validate-tests.yml \
	   -f testPackages="$${PKGS}" \
	   -f testRepeatCount="$${REPS}" \
	   -f runTestsWithRace="true" \
	   -f testRunner="$${RUNNER}"

help:
	@echo ""
	@echo "         .__           .__       .__  .__        __"
	@echo "    ____ |  |__ _____  |__| ____ |  | |__| ____ |  | __"
	@echo "  _/ ___\|  |  \\\\\\__  \ |  |/    \|  | |  |/    \|  |/ /"
	@echo "  \  \___|   Y  \/ __ \|  |   |  \  |_|  |   |  \    <"
	@echo "   \___  >___|  (____  /__|___|  /____/__|___|  /__|_ \\"
	@echo "       \/     \/     \/        \/             \/     \/"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
