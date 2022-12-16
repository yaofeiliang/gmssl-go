package main

import (
	"context"
	"github.com/moby/moby/pkg/pubsub"
	"google.golang.org/grpc"
	"log"
	"strings"
	"time"
)

// PubsubService 实现发布和订阅服务了
type PubsubService struct {
	pub *pubsub.Publisher
}

func NewPubsubService() *PubsubService {
	return &PubsubService{
		pub: pubsub.NewPublisher(100*time.Millisecond, 10),
	}
}

// Publish 实现发布方法和订阅方法：
func (p *PubsubService) Publish(
	ctx context.Context, arg *String,
) (*String, error) {
	p.pub.Publish(arg.GetValue())
	return &String{}, nil
}

func (p *PubsubService) Subscribe(
	arg *String, stream PubsubService_SubscribeServer,
) error {
	ch := p.pub.SubscribeTopic(func(v interface{}) bool {
		if key, ok := v.(string); ok {
			if strings.HasPrefix(key, arg.GetValue()) {
				return true
			}
		}
		return false
	})

	for v := range ch {
		if err := stream.Send(&String{Value: v.(string)}); err != nil {
			return err
		}
	}

	return nil
}

// 从客户端向服务器发布信息了：
func main() {
	conn, err := grpc.Dial("localhost:1234", grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := NewPubsubServiceClient(conn)

	_, err = client.Publish(
		context.Background(), &String{Value: "golang: hello Go"},
	)
	if err != nil {
		log.Fatal(err)
	}
	_, err = client.Publish(
		context.Background(), &String{Value: "docker: hello Docker"},
	)
	if err != nil {
		log.Fatal(err)
	}
}
