package vulners

import (
	"context"
	"grpc-nmap-vulners/pkg/logger"
	"grpc-nmap-vulners/pkg/proto"
	"log"
	"net"

	"google.golang.org/grpc"
)

// Server for functions implementation
type Server struct {
	proto.UnimplementedNetVulnServiceServer
}

// CheckVuln call implementation
func (s *Server) CheckVuln(_ context.Context, req *proto.CheckVulnRequest) (*proto.CheckVulnResponse, error) {
	return requestScanWithNmap(req)
}

// StartServer runs gRPC call listener
func StartServer(network string, address string, customLogget *log.Logger, logLevel int) {
	if logger.DEBUG >= logLevel {
		customLogget.Println("[DEBUG] binding port listener")
	}
	l, err := net.Listen(network, address)
	if err != nil {
		customLogget.Fatalf("[CRITICAL] failed to listen: %v", err)
	}

	if logger.DEBUG >= logLevel {
		customLogget.Println("[DEBUG] creating gRPC server")
	}
	grpcServer := grpc.NewServer()
	srv := &Server{}
	proto.RegisterNetVulnServiceServer(grpcServer, srv)

	if logger.DEBUG >= logLevel {
		customLogget.Println("[DEBUG] starting gRPC server")
	}
	if err := grpcServer.Serve(l); err != nil {
		customLogget.Fatalf("[CRITICAL] failed to serve: %v", err)
	}
	grpcServer.Stop()
}
