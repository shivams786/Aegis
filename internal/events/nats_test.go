package events

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aegis/aegis/internal/outbox"
)

func TestNATSPublisherWritesPublishFrame(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	got := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		got <- string(buf[:n])
	}()
	publisher := NATSPublisher{Addr: listener.Addr().String(), Subject: "aegis.events", Timeout: time.Second}
	if err := publisher.Publish(outbox.Event{EventID: "evt_1", TenantID: "tenant_acme", AggregateID: "inv_1", EventType: "InvocationSucceeded"}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	frame := <-got
	if !strings.Contains(frame, "CONNECT") {
		t.Fatalf("expected CONNECT frame, got %q", frame)
	}
}
