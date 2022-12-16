package main

import (
	"github.com/rongzer/gmssl-go/grpc"
	"github.com/rongzer/gmssl-go/grpc/credentials"
	"github.com/rongzer/gmssl-go/net/context"
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

// 生成server.key、server.crt、client.key和client.crt四个文件。
// 其中以.key为后缀名的是私钥文件，需要妥善保管。
// 以.crt为后缀名是证书文件，也可以简单理解为公钥文件，并不需要秘密保存。
// 在subj参数中的/CN=server.grpc.io表示服务器的名字为server.grpc.io

func main() {
	creds, err := credentials.NewServerTLSFromFile(
		"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmTlsGRPC/key2/certpem.cert",
		"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmTlsGRPC/key2/privPem.cert",
		//"/Users/yao/Desktop/zhaochuninhefei/gmgo/test/gmTlsGRPC/key/server.crt",
		//"/Users/yao/Desktop/zhaochuninhefei/gmgo/test/gmTlsGRPC/key/server.key",
	)

	if err != nil {
		log.Fatal(err)
	}

	//grpcServer := grpc.NewServer()
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	RegisterHelloServiceServer(grpcServer, new(HelloServiceImpl))

	lis, err := net.Listen("tcp", ":1234")
	if err != nil {
		log.Fatal(err)
	}
	grpcServer.Serve(lis)
}
