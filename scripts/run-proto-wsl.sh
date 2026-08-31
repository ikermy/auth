#!/bin/sh
set -e
PLUGIN=/tmp/ts-proto-plugin
printf '#!/bin/sh\nexec node /mnt/d/prod/barcode-system/auth/node_modules/ts-proto/protoc-gen-ts_proto "$@"\n' > "$PLUGIN"
chmod +x "$PLUGIN"
protoc --plugin=protoc-gen-ts_proto="$PLUGIN" \
  --ts_proto_out=./ \
  --ts_proto_opt=outputServices=grpc-js,env=node,esModuleInterop=true,esModuleImpl=true,esModulePrefix=true,addGrpcMetadata=true,oneof=unions,outputJsonMethods=false \
  ./src/auth/auth.proto
echo "PROTO_GENERATED_OK"
