package main

import (
	"fmt"
	"github.com/rongzer/gmssl-go/grpc"
	"github.com/rongzer/gmssl-go/grpc/credentials"
	"github.com/rongzer/gmssl-go/net/context"
	"log"
)

func main() {
	creds, err := credentials.NewClientTLSFromFile(
		"/Users/yao/Documents/rongzer/gowork/src/gmssl-go/test/gmTlsGRPC/key2/certpem.cert",
		"localhost",
	)
	if err != nil {
		log.Fatal(err)
	}
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
