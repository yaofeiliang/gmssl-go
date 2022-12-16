https://blog.csdn.net/lt4959/article/details/86305608
https://www.cnblogs.com/f-ck-need-u/p/6091027.html

生成密钥对(私钥）
~~~~

gmssl ecparam -genkey -name sm2p256v1 -text -out sm2.key
gmssl ec -in sm2.key -pubout -out pk.pem

~~~~
生成CA证书
~~~~
mkdir /Users/yao/demoCA

cd  /Users/yao/demoCA

# 在此路径下创建好newcerts、private、certs、crl子目录，同时创建index.txt、serial文件。
mkdir newcerts private certs crl touch index.txt
# 创建serial，并写入初始化序号，如01
vi serial

创建的子目录及文件的含义：
certs：存放已颁发的证书；
newcerts：存放CA指令生成的新证书；
private：存放私钥；
crl：存放已吊销的整数；
index.txt：penSSL定义的已签发证书的文本数据库文件，这个文件通常在初始化的时候是空的；
serial：证书签发时使用的序列号参考文件，该文件的序列号是以16进制格式进行存放的，该文件必须提供并且包含一个有效的序列号。



gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve -out private/cakey.pem

gmssl req -new -x509 -key private/cakey.pem -out cacert.pem

openssl x509 -in cacert.pem -noout -text


~~~~
生成用户证书请求
~~~
gmssl req -new -key private/cakey.pem -out serverreq.pem
~~~
用CA证书签名生成用户证书

gmssl ca -in serverreq.pem -out servercert.pem
