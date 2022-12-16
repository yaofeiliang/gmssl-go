package main

import (
	"fmt"
	tls "github.com/rongzer/gmssl-go/gmtls"
	"github.com/rongzer/gmssl-go/grpc"
	"github.com/rongzer/gmssl-go/grpc/credentials"
	"github.com/rongzer/gmssl-go/net/context"
	"github.com/rongzer/gmssl-go/x509"
	"io/ioutil"
	"log"
)

func main() {
	//creds, err := credentials.NewClientTLSFromFile(
	//	"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmTlsGRPC/key2/certpem.cert",
	//	"localhost",
	//)

	//if err != nil {
	//	log.Fatal(err)
	//}
	//

	////"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/cakey/client.crt"
	////"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/cakey/client.key"
	certificate, err := tls.LoadX509KeyPair(
		"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/clientCertPem.crt",
		"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/clientKey.crt")
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmCATlsGRPC/gmcakey/caCertPem.crt")
	if err != nil {
		log.Fatal(err)
	}
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatal("failed to append ca certs")
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ServerName:   "server.io", // NOTE: this is required!
		RootCAs:      certPool,
	})
	//conn, err := grpc.Dial("localhost:1234", grpc.WithInsecure())
	conn, err := grpc.Dial("localhost:1234",
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := NewHelloServiceClient(conn)
	reply, err := client.Hello(context.Background(), &String{Value: "hello"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(reply.GetValue())
}
