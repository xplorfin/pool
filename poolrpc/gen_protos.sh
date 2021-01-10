#!/bin/sh

set -e

# Generate the gRPC bindings for all proto files.
for file in ./*.proto
do
	protoc -I/usr/local/include -I. \
	       -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
	       --go_out=plugins=grpc,paths=source_relative:. \
		${file}

done

protoc -I/usr/local/include -I. \
       -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
       --grpc-gateway_out=logtostderr=true,paths=source_relative:. \
       trader.proto

protoc -I/usr/local/include -I. \
       -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
       --swagger_out=logtostderr=true:. \
       trader.proto

protoc -I/usr/local/include -I. \
       -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
       --grpc-gateway_out=logtostderr=true,paths=source_relative:. \
       initializer.proto

protoc -I/usr/local/include -I. \
       -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
       --swagger_out=logtostderr=true:. \
       initializer.proto
