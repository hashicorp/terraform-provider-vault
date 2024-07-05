TEST ?= $$(go list ./...)
GOFMT_FILES ?= $$(find . -name '*.go')
WEBSITE_REPO = github.com/hashicorp/terraform-website
PKG_NAME = vault
TF_ACC_TERRAFORM_VERSION ?= 1.2.2
TESTARGS ?= -test.v
TEST_PATH ?= ./...

go-version-check: ## Check go version
	@sh -c $(CURDIR)/scripts/goversioncheck.sh

default: build

build: go-version-check fmtcheck
	go install

test: go-version-check fmtcheck
	TF_ACC= VAULT_TOKEN= go test $(TESTARGS) -timeout 10m $(TEST_PATH)

testsum: go-version-check fmtcheck
	TF_ACC= VAULT_TOKEN= gotestsum $(TEST_PATH) $(TESTARGS) -test.timeout 10m

testacc: fmtcheck
	TF_ACC=1 go test $(TESTARGS) -timeout 30m $(TEST_PATH)

testaccsum: fmtcheck
	TF_ACC=1 gotestsum $(TEST_PATH) $(TESTARGS) -timeout 30m

testacc-ent:
	make testacc TF_ACC_ENTERPRISE=1

testaccsum-ent:
	make testaccsum TF_ACC_ENTERPRISE=1

dev: go-version-check fmtcheck
	go build -o terraform-provider-vault
	mv terraform-provider-vault ~/.terraform.d/plugins/

debug: go-version-check fmtcheck
	go build -gcflags "all=-N -l" -o terraform-provider-vault
	mv terraform-provider-vault ~/.terraform.d/plugins/

vet:
	@echo "go vet ."
	@go vet $$(go list ./...) ; if [ $$? -eq 1 ]; then \
		echo ""; \
		echo "Vet found suspicious constructs. Please check the reported constructs"; \
		echo "and fix them if necessary before submitting the code for review."; \
		exit 1; \
	fi

fmt:
	gofmt -s -w $(GOFMT_FILES)

fmtcheck: go-version-check
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

errcheck:
	@sh -c "'$(CURDIR)/scripts/errcheck.sh'"

test-compile:
	@if [ "$(TEST)" = "./..." ]; then \
		echo "ERROR: Set TEST to a specific package. For example,"; \
		echo "  make test-compile TEST=./$(PKG_NAME)"; \
		exit 1; \
	fi
	go test -c $(TEST) $(TESTARGS)

website:
ifeq (,$(wildcard $(GOPATH)/src/$(WEBSITE_REPO)))
	echo "$(WEBSITE_REPO) not found in your GOPATH (necessary for layouts and assets), get-ting..."
	git clone https://$(WEBSITE_REPO) $(GOPATH)/src/$(WEBSITE_REPO)
endif
	@$(MAKE) -C $(GOPATH)/src/$(WEBSITE_REPO) website-provider PROVIDER_PATH=$(shell pwd) PROVIDER_NAME=$(PKG_NAME)

website-test:
ifeq (,$(wildcard $(GOPATH)/src/$(WEBSITE_REPO)))
	echo "$(WEBSITE_REPO) not found in your GOPATH (necessary for layouts and assets), get-ting..."
	git clone https://$(WEBSITE_REPO) $(GOPATH)/src/$(WEBSITE_REPO)
endif
	@$(MAKE) -C $(GOPATH)/src/$(WEBSITE_REPO) website-provider-test PROVIDER_PATH=$(shell pwd) PROVIDER_NAME=$(PKG_NAME)

.PHONY: build test testacc testacc-ent vet fmt fmtcheck errcheck test-compile website website-test go-version-check testaccsum testaccsum-ent
