VERSION 						?= $(shell git describe --tags --always --dirty)
GIT_COMMIT          ?= $(shell git rev-list -1 HEAD)
RELEASE_VERSION			= $(shell git describe --abbrev=0 --tag)

GO_BUILD_ENV_VARS						?= GO111MODULE=on 
GO_BUILD_ENV_TEST_VARS			?= GO111MODULE=on GOMAXPROCS=1

GO_TEST 				?= $(GO_BUILD_ENV_TEST_VARS) go test -race -timeout 30s -v -covermode=atomic -coverprofile=single.coverprofile

.PHONY: test clean benchmark build-test-helper

clean:
	rm -f *.coverprofile
	rm -f test-helper
	rm -f test-helper_linux_amd64

test-helper:
	$(GO_BUILD_ENV_VARS) go build -o test-helper ./cmd/krach-test

test-helper_linux_amd64:
	$(GO_BUILD_ENV_VARS) GOOS=linux GOARCH=amd64 go build -o test-helper_linux_amd64 ./cmd/krach-test

build-test-helper: test-helper test-helper_linux_amd64

benchmark:
	$(GO_BUILD_ENV_TEST_VARS) go test -timeout 30s -v -benchmem -bench=.

test:
	$(GO_TEST) ./
