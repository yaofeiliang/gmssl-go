package main

import (
	"fmt"
	"log"
	"net/rpc"
)

// HelloServiceName 明确服务的名字和接口
const HelloServiceName = "path/to/pkg.HelloService"

type HelloServiceInterface = interface {
	Hello(request string, reply *string) error
}

//func RegisterHelloService(svc HelloServiceInterface) error {
//    return rpc.RegisterName(HelloServiceName, svc)
//}

//============================================

type HelloServiceClient struct {
	*rpc.Client
}

var _ HelloServiceInterface = (*HelloServiceClient)(nil)

func DialHelloService(network, address string) (*HelloServiceClient, error) {
	c, err := rpc.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return &HelloServiceClient{Client: c}, nil
}

func (p *HelloServiceClient) Hello(request string, reply *string) error {
	return p.Client.Call(HelloServiceName+".Hello", request, reply)
}

func main() {
	// 通过rpc.Dial拨号RPC服务
	//client, err := rpc.Dial("tcp", "localhost:1234")

	client, err := DialHelloService("tcp", "localhost:1234")

	if err != nil {
		log.Fatal("dialing:", err)
	}

	var reply string
	// client.Call调用具体的RPC方法
	// 第一个参数是用点号链接的RPC服务名字和方法名字，
	// 第二和第三个参数分别我们定义RPC方法的两个参数
	//err = client.Call("HelloService.Hello", "hello", &reply)

	// 其中唯一的变化是client.Call的第一个参数用HelloServiceName+".Hello"代替了"HelloService.Hello"。
	// 然而通过client.Call函数调用RPC方法依然比较繁琐，同时参数的类型依然无法得到编译器提供的安全保障。
	//err = client.Call(HelloServiceName+".Hello", "hello", &reply)
	err = client.Hello("hello", &reply)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(reply)
}
