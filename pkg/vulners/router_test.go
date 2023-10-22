package vulners

import (
	"context"
	"grpc-nmap-vulners/pkg/logger"
	"grpc-nmap-vulners/pkg/proto"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestStartServer(t *testing.T) {
	network := "tcp"
	address := "127.0.0.1:8080"
	customLogger := log.New(os.Stdout, "", 0)
	logLevel := logger.DEBUG

	go func() {
		StartServer(network, address, customLogger, logLevel)
	}()
	time.Sleep(1 * time.Second)
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()
	client := proto.NewNetVulnServiceClient(conn)

	req := &proto.CheckVulnRequest{
		Targets: []string{"127.0.0.1"},
		TcpPort: []int32{80, 443},
	}
	response, err := client.CheckVuln(context.Background(), req)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	assert.Equal(t, response.Results[0].Target, "127.0.0.1")
	if response.Results[0].Services[0].TcpPort == 443 {
		assert.Equal(t, response.Results[0].Services[0].Name, "https")
		assert.Equal(t, response.Results[0].Services[1].Name, "http")
	} else {
		assert.Equal(t, response.Results[0].Services[0].Name, "http")
		assert.Equal(t, response.Results[0].Services[1].Name, "https")
	}
}
