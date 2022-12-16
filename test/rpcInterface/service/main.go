package main

import (
	"log"
	"net"
	"net/rpc"
)

// HelloServiceName 明确服务的名字和接口
const HelloServiceName = "path/to/pkg.HelloService"

type HelloServiceInterface = interface {
	Hello(request string, reply *string) error
}

// RegisterHelloService rpc 注册服务 通过接口
func RegisterHelloService(svc HelloServiceInterface) error {
	return rpc.RegisterName(HelloServiceName, svc)
}

type HelloService struct{}

func (p *HelloService) Hello(request string, reply *string) error {
	*reply = "hello:" + request
	return nil
}

// 服务端实现RPC方法的开发人员
// 客户端调用RPC方法的人员
// 制定服务端和客户端RPC接口规范的设计人员
func main() {
	// 将对象类型中所有满足RPC规则的对象方法注册为RPC函数，
	// 所有注册的方法会放在“HelloService”服务空间之下
	//rpc.RegisterName("HelloService", new(HelloService))
	err := RegisterHelloService(new(HelloService))
	if err != nil {
		return
	}

	listener, err := net.Listen("tcp", ":1234")
	if err != nil {
		log.Fatal("ListenTCP error:", err)
	}

	conn, err := listener.Accept()
	if err != nil {
		log.Fatal("Accept error:", err)
	}

	rpc.ServeConn(conn)
}
