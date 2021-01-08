all: vet test testrace

build: deps
	go build github.com/CloudmindsRobot/gmgo/grpc/...

clean:
	go clean -i github.com/CloudmindsRobot/gmgo/grpc/...

deps:
	go get -d -v github.com/CloudmindsRobot/gmgo/grpc/...

proto:
	@ if ! which protoc > /dev/null; then \
		echo "error: protoc not installed" >&2; \
		exit 1; \
	fi
	go generate github.com/CloudmindsRobot/gmgo/grpc/...

test: testdeps
	go test -cpu 1,4 -timeout 7m github.com/CloudmindsRobot/gmgo/grpc/...

testsubmodule: testdeps
	cd security/advancedtls && go test -cpu 1,4 -timeout 7m github.com/CloudmindsRobot/gmgo/grpc/security/advancedtls/...
	cd security/authorization && go test -cpu 1,4 -timeout 7m github.com/CloudmindsRobot/gmgo/grpc/security/authorization/...

testappengine: testappenginedeps
	goapp test -cpu 1,4 -timeout 7m github.com/CloudmindsRobot/gmgo/grpc/...

testappenginedeps:
	goapp get -d -v -t -tags 'appengine appenginevm' github.com/CloudmindsRobot/gmgo/grpc/...

testdeps:
	go get -d -v -t github.com/CloudmindsRobot/gmgo/grpc/...

testrace: testdeps
	go test -race -cpu 1,4 -timeout 7m github.com/CloudmindsRobot/gmgo/grpc/...

updatedeps:
	go get -d -v -u -f github.com/CloudmindsRobot/gmgo/grpc/...

updatetestdeps:
	go get -d -v -t -u -f github.com/CloudmindsRobot/gmgo/grpc/...

vet: vetdeps
	./vet.sh

vetdeps:
	./vet.sh -install

.PHONY: \
	all \
	build \
	clean \
	deps \
	proto \
	test \
	testappengine \
	testappenginedeps \
	testdeps \
	testrace \
	updatedeps \
	updatetestdeps \
	vet \
	vetdeps
