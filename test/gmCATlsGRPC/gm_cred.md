可以用以下命令为服务器和客户端分别生成私钥和证书：

~~~
$ openssl genrsa -out server.key 2048

 gmssl ecparam -genkey -name sm2p256v1 -text -out server.key

$ openssl req -new -x509 -days 3650 \
-subj "/C=GB/L=China/O=grpc-server/CN=server.grpc.io" \
-key server.key -out server.crt

 gmssl ec -in sm2.key -pubout -out server.crt

# > openssl req -out server.csr -key server.key -new

openssl req -new \
-subj "/C=GB/L=China/O=server/CN=server.io" \
-key server.key \
-out server.csr

添加附加 SAN -extfile san.txt。

> openssl x509 -req -days 3650 -signkey server.key -in server.csr -out server.crt -extfile san.txt

检查是否连接了 SAN。

> openssl x509 -text -in sample.crt -noout


$ openssl genrsa -out client.key 2048

$ openssl req -new -x509 -days 3650 \
-subj "/C=GB/L=China/O=grpc-client/CN=client.grpc.io" \
-key client.key -out client.crt
~~~

以上命令将生成server.key、server.crt、client.key和client.crt四个文件。
其中以.key为后缀名的是私钥文件，需要妥善保管。
以.crt为后缀名是证书文件，也可以简单理解为公钥文件，并不需要秘密保存。
在subj参数中的/CN=server.grpc.io表示服务器的名字为server.grpc.io，
在验证服务器的证书时需要用到该信息。


为了避免证书的传递过程中被篡改，可以通过一个安全可靠的根证书分别对服务器和客户端的证书进行签名。
这样客户端或服务器在收到对方的证书后可以通过根证书进行验证证书的有效性。
根证书的生成方式和自签名证书的生成方式类似：

~~~
$ openssl genrsa -out ca.key 2048
$ openssl req -new -x509 -days 3650 \
-subj "/C=GB/L=China/O=gobook/CN=github.com" \
-key ca.key -out ca.crt
~~~
然后是重新对服务器端证书进行签名：
~~~
$ openssl req -new \
-subj "/C=GB/L=China/O=server/CN=server.io" \
-key server.key \
-out server.csr

$ openssl x509 -req -sha256 \
-CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
-in server.csr \
-out server.crt
~~~

如果客户端的证书也采用CA根证书签名的话，
服务器端也可以对客户端进行证书认证。
我们用CA根证书对客户端证书签名：

~~~
$ openssl req -new \
    -subj "/C=GB/L=China/O=client/CN=client.io" \
    -key client.key \
    -out client.csr
$ openssl x509 -req -sha256 \
    -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
    -in client.csr \
    -out client.crt
~~~
