package vulners

import (
	"context"
	"grpc-nmap-vulners/pkg/proto"
)

// Server for functions implementation
type Server struct {
	proto.UnimplementedNetVulnServiceServer
}

// CheckVuln call implementation
func (s *Server) CheckVuln(_ context.Context, req *proto.CheckVulnRequest) (*proto.CheckVulnResponse, error) {
	return requestScanWithNmap(req)
}
