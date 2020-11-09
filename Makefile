PLUGIN_NAME="caddy-jwt-valid"
PLUGIN_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
LATEST_GIT_COMMIT:=$(shell git log --format="%H" -n 1 | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
BUILD_DIR:=$(shell pwd)
VERBOSE:=-v
#GO_OS:=$(shell echo $(uname) | tr '[:upper:]' '[:lower:]')
GO_OS=linux
ifdef TEST
	TEST:="-run ${TEST}"
endif
CADDY_VERSION="v2.2.1"

all:
	@echo "Version: $(PLUGIN_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "Build on $(BUILD_DATE) by $(BUILD_USER)"
	@mkdir -p bin/
	@rm -rf ./bin/
	@mkdir -p ./bin/xcaddy && cd ./bin/xcaddy && \
	env GOARCH=amd64 GOOS=$(GO_OS) xcaddy build $(CADDY_VERSION) --output ../caddy \
		    --with github.com/amalto/$(PLUGIN_NAME)@$(LATEST_GIT_COMMIT)=$(BUILD_DIR)
	@rm -rf ./bin/xcaddy

linter:
	@echo "Running lint checks"
	@golint *.go
	@echo "PASS: golint"

test: covdir linter
	@go test $(VERBOSE) -coverprofile=.coverage/coverage.out ./*.go

ctest: covdir linter
	@time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./*.go

covdir:
	@echo "Creating .coverage/ directory"
	@mkdir -p .coverage

coverage:
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@go test -covermode=count -coverprofile=.coverage/coverage.out ./*.go
	@go tool cover -func=.coverage/coverage.out | grep -v "100.0"

docs:
	@mkdir -p .doc
	@go doc -all > .doc/index.txt

clean:
	@rm -rf .doc
	@rm -rf .coverage
	@rm -rf bin/

qtest: covdir
	@echo "Perform quick tests ..."
	@go test $(VERBOSE) -coverprofile=.coverage/coverage.out -run TestCaddyfile ./*.go

dep:
	@echo "Making dependencies check ..."
	@go get -u golang.org/x/lint/golint
	@go get -u golang.org/x/tools/cmd/godoc
	@go get -u github.com/kyoh86/richgo
	@go get -u github.com/caddyserver/xcaddy/cmd/xcaddy
