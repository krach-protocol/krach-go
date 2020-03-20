VERSION 						?= $(shell git describe --tags --always --dirty)
GIT_COMMIT          ?= $(shell git rev-list -1 HEAD)
RELEASE_VERSION			= $(shell git describe --abbrev=0 --tag)

GO_BUILD_ENV_VARS						?= GO111MODULE=on 
GO_BUILD_ENV_TEST_VARS			?= GO111MODULE=on GOMAXPROCS=1

GO_TEST 				?= $(GO_BUILD_ENV_TEST_VARS) go test -timeout 30s -v -covermode=atomic -coverprofile=single.coverprofile # Disable -race for now

.PHONY: test clean benchmark

clean:
	rm -f *.coverprofile

benchmark:
	$(GO_BUILD_ENV_TEST_VARS) go test -v -benchmem -bench=.

test:
	$(GO_TEST)