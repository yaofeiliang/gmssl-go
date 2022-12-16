package main

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"log"
)

func main() {
	conn, err := grpc.Dial("localhost:12345", grpc.WithInsecure())
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
