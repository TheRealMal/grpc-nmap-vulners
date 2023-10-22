package vulners

import (
	"context"
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
func StartServer(network string, address string) {
	l, err := net.Listen(network, address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	srv := &Server{}
	proto.RegisterNetVulnServiceServer(grpcServer, srv)

	if err := grpcServer.Serve(l); err != nil {
		log.Fatal(err)
	}
}
