package main

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"log"
	"net"
)

type HelloServiceImpl struct{}

// Channel 实现流服务
func (p *HelloServiceImpl) Channel(stream HelloService_ChannelServer) error {
	for {
		args, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		reply := &String{Value: "hello:" + args.GetValue()}

		err = stream.Send(reply)
		if err != nil {
			return err
		}
	}
}

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

	lis, err := net.Listen("tcp", ":12345")
	if err != nil {
		log.Fatal(err)
	}
	grpcServer.Serve(lis)
}
