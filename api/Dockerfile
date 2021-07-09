FROM golang:1.15.13-stretch

RUN apt-get update \
    && apt-get install -y unzip

RUN GO111MODULE=on go get -u google.golang.org/protobuf/cmd/protoc-gen-go@v1.26 \
    && git clone --depth 1 --branch v1.39.0 https://github.com/grpc/grpc-go /go/src/google.golang.org/grpc \
    && cd /go/src/google.golang.org/grpc/cmd/protoc-gen-go-grpc \
    && go install ./... \
    && mkdir -p /tmp/protoc \
    && cd /tmp/protoc \
    && curl -L https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protoc-3.17.3-linux-x86_64.zip \
        --output /tmp/protoc-3.17.3-linux-x86_64.zip \
    && unzip /tmp/protoc-3.17.3-linux-x86_64.zip \
    && mv include/ /usr/local/ \
    && mv bin/protoc /usr/bin/
