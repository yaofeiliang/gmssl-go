package main

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"io"
	"log"
	"time"
)

func main() {
	conn, err := grpc.Dial("localhost:12345", grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := NewHelloServiceClient(conn)
	//reply, err := client.Hello(context.Background(), &String{Value: "hello"})
	// 调用Channel方法获取返回的流对象：
	stream, err := client.Channel(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	// 向服务端发送数据：
	go func() {
		for {
			if err := stream.Send(&String{Value: "hi"}); err != nil {
				log.Fatal(err)
			}
			time.Sleep(time.Second)
		}
	}()
	// 接收服务端返回的数据
	for {
		reply, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		fmt.Println(reply.GetValue())
	}
}
