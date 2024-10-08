# Build target
TARGET=github.com/securesharelabs/vstore
BIN=$(shell pwd)/vstore

GIT_TAG=`git describe --exact-match --tags`
GOPROXY=proxy.golang.org

build:
	go build
	go test github.com/securesharelabs/vstore/vfs -count=1
	@echo "Build successful!"
	@echo "Binary: ${BIN}"

release:
	GOPROXY=${GOPROXY} go list -m ${TARGET}@${GIT_TAG}
	@echo "Successfully released ${TARGET}@${GIT_TAG}!"

.PHONY: docs
docs:
	gopages -out docs/ -base "https://vfs.zone" -brand-title "vStore/vfs ${GIT_TAG}" -brand-description "Reference documentation"
	@echo "Successfully generated documentation!"
