package main

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
)

// 通过nc命令nc -l 1234在同样的端口启动一个TCP服务
// $ nc -l 1234
// 然后再次执行一次RPC调用将会发现nc输出了以下的信息：
//{"method":"HelloService.Hello","params":["hello"],"id":0}

func main() {
	// 先手工调用net.Dial函数建立TCP链接
	conn, err := net.Dial("tcp", "localhost:1234")
	if err != nil {
		log.Fatal("net.Dial:", err)
	}
	// 基于该链接建立针对客户端的json编解码器
	client := rpc.NewClientWithCodec(jsonrpc.NewClientCodec(conn))

	var reply string
	err = client.Call("HelloService.Hello", "hello", &reply)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(reply)
}
