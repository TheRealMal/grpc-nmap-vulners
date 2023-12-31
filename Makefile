DIR=$(shell pwd)
SERVER=server
CLI=cli

build:
	go build -o $(SERVER) $(DIR)/cmd/server/...

$(SERVER):
	go build -o $(SERVER) $(DIR)/cmd/server/...

run: $(SERVER)
	./$(SERVER)

lint:
	golangci-lint -c $(DIR)/.golangci.yml run $(DIR)/pkg/proto/...
	golangci-lint -c $(DIR)/.golangci.yml run $(DIR)/pkg/vulners/...
	golangci-lint -c $(DIR)/.golangci.yml run $(DIR)/pkg/logger/...
	golangci-lint -c $(DIR)/.golangci.yml run $(DIR)/cmd/$(CLI)/...
	golangci-lint -c $(DIR)/.golangci.yml run $(DIR)/cmd/$(SERVER)/...

test:
	go test ./...

coverage:
	go test -coverprofile=cover.out ./...
	go tool cover -html=cover.out -o coverage.html
	rm cover.out

clean:
	rm ./$(SERVER)

# Some CLI targets

build-cli:
	go build $(DIR)/cmd/$(CLI)/...

clean-cli:
	rm ./$(CLI)

# Protoc

protoc-gen:
protoc --go_out=./pkg/ --go_opt=paths=source_relative --go-grpc_out=./pkg/ --go-grpc_opt=paths=source_relative ./api/vulners.proto