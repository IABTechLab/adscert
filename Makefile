
# generate protobuf/grpc code
build-protoc-env:
	@echo ">>> building protoc environment"
	DOCKER_SCAN_SUGGEST=false docker build . -f api/Dockerfile --tag adscert-protoc-env:latest

build-protoc: build-protoc-env
	@echo ">>> building protoc environment"
	docker run \
		-v $$(pwd):/go/src/github.com/IABTechLab/adscert \
		-w /go/src/github.com/IABTechLab/adscert \
		-it adscert-protoc-env:latest \
		protoc \
			--go_out=./pkg/adscert/api \
			--go_opt=module=github.com/IABTechLab/adscert/pkg/adscert/api \
			--go-grpc_out=./ \
			--go-grpc_opt=module=github.com/IABTechLab/adscert \
			./api/adscert.proto

build-grpc-server:
	@echo ">>> build grpc/server app"
	go build ./cmd/server

build-grpc-server-container:
	@echo ">>> build docker container"
	docker build -t adscert:latest .
