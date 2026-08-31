#!/bin/sh
set -e
export PATH="$PWD/node_modules/.bin:$PATH"
protoc --plugin=protoc-gen-ts_proto=protoc-gen-ts_proto \
  --ts_proto_out=./ \
  --ts_proto_opt=outputServices=grpc-js,env=node,esModuleInterop=true,esModuleImpl=true,esModulePrefix=true,addGrpcMetadata=true,oneof=unions,outputJsonMethods=false \
  ./src/auth/auth.proto
