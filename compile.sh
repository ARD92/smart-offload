protoc --proto_path=proto/ proto/jnx_routing_base_types.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
protoc --proto_path=proto/ proto/jnx_routing_bgp_service.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
protoc --proto_path=proto/ proto/jnx_authentication_service.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
protoc --proto_path=proto/ proto/jnx_common_addr_types.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
protoc --proto_path=proto/ proto/jnx_common_base_types.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
protoc --proto_path=proto/ proto/jnx_management_service.proto --go_out=plugins=grpc:. --plugin=protoc-gen-go=/go/bin/protoc-gen-go
