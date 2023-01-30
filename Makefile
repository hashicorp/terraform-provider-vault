TEST ?= $$(go list ./...)
GOFMT_FILES ?= $$(find . -name '*.go')
WEBSITE_REPO = github.com/hashicorp/terraform-website
PKG_NAME = vault
TF_ACC_TERRAFORM_VERSION ?= 1.2.2
TESTARGS ?= -test.v
TEST_PATH ?= ./...

default: build

build: fmtcheck
	go install

test: fmtcheck
	TF_ACC= go test $(TESTARGS) -timeout 10m -parallel=4 $(TEST_PATH)

testacc: fmtcheck
	TF_ACC=1 go test $(TESTARGS) -timeout 30m $(TEST_PATH)

testacc-ent:
	make testacc TF_ACC_ENTERPRISE=1

dev: fmtcheck
	go build -o terraform-provider-vault
	mv terraform-provider-vault ~/.terraform.d/plugins/

debug: fmtcheck
	go build -gcflags "all=-N -l" -o terraform-provider-vault
	mv terraform-provider-vault ~/.terraform.d/plugins/

generate:
	result=$(cd generated && find . -type f -not -name '*_test.go' | grep -v 'registry.go' | xargs rm && cd - )
	go run cmd/generate/main.go -openapi-doc=testdata/openapi.json
	make fmt

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

fmtcheck:
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

.PHONY: build test testacc testacc-ent vet fmt fmtcheck errcheck test-compile website website-test
