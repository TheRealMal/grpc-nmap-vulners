# gRPC nmap vulners
## develop
### Generate Go gRPC files
```console
protoc --go_out=./pkg/ --go_opt=paths=source_relative --go-grpc_out=./pkg/ --go-grpc_opt=paths=source_relative ./api/vulners.proto
```