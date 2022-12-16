package main

import (
	"io"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
)

type HelloService struct{}

func (p *HelloService) Hello(request string, reply *string) error {
	*reply = "hello:" + request
	return nil
}

func main() {
	err := rpc.RegisterName("HelloService", new(HelloService))
	if err != nil {
		return
	}
	// RPC的服务架设在“/jsonrpc”路径
	http.HandleFunc("/jsonrpc", func(w http.ResponseWriter, r *http.Request) {
		// 处理函数中基于http.ResponseWriter和http.Request类型的参数构造一个io.ReadWriteCloser类型的conn通道
		var conn io.ReadWriteCloser = struct {
			io.Writer
			io.ReadCloser
		}{
			ReadCloser: r.Body,
			Writer:     w,
		}
		// 基于conn构建针对服务端的json编码解码器。最后通过rpc.ServeRequest函数为每次请求处理一次RPC方法调用。
		err := rpc.ServeRequest(jsonrpc.NewServerCodec(conn))
		if err != nil {
			return
		}
	})

	err = http.ListenAndServe(":1234", nil)
	if err != nil {
		return
	}
}
