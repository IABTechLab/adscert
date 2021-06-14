# generate protobuf/grpc code
protoc --go_out=. --go_opt=module=github.com/IABTechLab/adscert --go-grpc_out=. --go-grpc_opt=module=github.com/IABTechLab/adscert ./api/adscert.proto

# build grpc/server app
go build ./cmd/server

# build docker container
### docker build -t adscert:latest .
