package main

import (
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
)

type HelloService struct{}

func (p *HelloService) Hello(request string, reply *string) error {
	*reply = "hello:" + request
	return nil
}

// 在获取到RPC调用对应的json数据后，我们可以通过直接向架设了RPC服务的TCP服务器发送json数据模拟RPC方法调用：
// $ echo -e '{"method":"HelloService.Hello","params":["hello"],"id":1}' | nc localhost 1234
// 返回的结果也是一个json格式的数据：
// {"id":1,"result":"hello:hello","error":null}

func main() {
	err := rpc.RegisterName("HelloService", new(HelloService))
	if err != nil {
		return
	}

	listener, err := net.Listen("tcp", ":1234")
	if err != nil {
		log.Fatal("ListenTCP error:", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal("Accept error:", err)
		}
		// rpc.ServeConn(conn)
		// rpc.ServeCodec函数替代了rpc.ServeConn函数，传入的参数是针对服务端的json编解码器
		go rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}
