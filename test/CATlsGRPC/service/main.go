package main

import (
	tls "github.com/rongzer/gmssl-go/gmtls"
	"github.com/rongzer/gmssl-go/grpc"
	"github.com/rongzer/gmssl-go/grpc/credentials"
	"github.com/rongzer/gmssl-go/net/context"
	"github.com/rongzer/gmssl-go/x509"
	"io/ioutil"
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
	//creds, err := credentials.NewServerTLSFromFile(
	//	"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/cakey/server.crt",
	//	"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/cakey/server.key",
	//	//"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/key/server.crt",
	//	//"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/key/server.key",
	//)
	//
	//if err != nil {
	//	log.Fatal(err)
	//}
	certificate, err := tls.LoadX509KeyPair(
		"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/CATlsGRPC/cakey/server.crt",
		"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/CATlsGRPC/cakey/server.key")
	if err != nil {
		log.Fatal(err)
	}

	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/CATlsGRPC/cakey/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatal("failed to append certs")
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert, // NOTE: this is optional!
		ClientCAs:    certPool,
	})

	//grpcServer := grpc.NewServer()
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	RegisterHelloServiceServer(grpcServer, new(HelloServiceImpl))

	lis, err := net.Listen("tcp", ":1234")
	if err != nil {
		log.Fatal(err)
	}
	grpcServer.Serve(lis)
}
