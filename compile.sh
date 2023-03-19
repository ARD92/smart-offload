protoc --proto_path=proto/ proto/authentication_service.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
#protoc --proto_path=proto/ proto/jnx_addr.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
#protoc --proto_path=proto/ proto/jnx_base_types.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
protoc --proto_path=proto/ proto/jnx_common_base_types.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
protoc --proto_path=proto/ proto/jnx_common_addr_types.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
protoc --proto_path=proto/ proto/jnx_firewall_service.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
