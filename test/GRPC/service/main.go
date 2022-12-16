package main

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"log"
	"net"
)

type HelloServiceImpl struct{}

func (p *HelloServiceImpl) mustEmbedUnimplementedHelloServiceServer() {
	//TODO implement me
	panic("implement me")
}

func (p *HelloServiceImpl) Hello(
	ctx context.Context, args *String,
) (*String, error) {
	reply := &String{Value: "hello:" + args.GetValue()}
	return reply, nil
}

func main() {
	grpcServer := grpc.NewServer()
	RegisterHelloServiceServer(grpcServer, new(HelloServiceImpl))

	lis, err := net.Listen("tcp", ":1234")
	if err != nil {
		log.Fatal(err)
	}
	grpcServer.Serve(lis)
}
