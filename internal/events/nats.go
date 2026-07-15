package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/aegis/aegis/internal/outbox"
)

type NATSPublisher struct {
	Addr    string
	Subject string
	Timeout time.Duration
}

func (p NATSPublisher) Publish(event outbox.Event) error {
	if p.Addr == "" || p.Subject == "" {
		return errors.New("nats publisher is not configured")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(context.Background(), "tcp", p.Addr)
	if err != nil {
		return fmt.Errorf("connect nats: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintf(conn, "CONNECT {\"verbose\":false,\"pedantic\":false}\r\n"); err != nil {
		return err
	}
	subject := strings.ReplaceAll(p.Subject, " ", "_")
	if _, err := fmt.Fprintf(conn, "PUB %s %d\r\n%s\r\n", subject, len(payload), payload); err != nil {
		return err
	}
	if _, err := fmt.Fprint(conn, "PING\r\n"); err != nil {
		return err
	}
	return nil
}
