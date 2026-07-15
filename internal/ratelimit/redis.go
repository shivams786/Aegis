package ratelimit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type RedisLimiter struct {
	Addr    string
	Prefix  string
	Timeout time.Duration
}

func (l RedisLimiter) Check(ctx context.Context, key string, rule Rule) (Decision, error) {
	if l.Addr == "" {
		return Decision{}, errors.New("redis limiter is not configured")
	}
	if rule.Limit <= 0 || rule.Window <= 0 {
		return Decision{Allowed: true}, nil
	}
	timeout := l.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", l.Addr)
	if err != nil {
		if rule.Strict {
			return Decision{}, fmt.Errorf("redis unavailable in strict mode: %w", err)
		}
		return Decision{Allowed: true}, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	redisKey := l.Prefix + key
	count, err := redisCommandInt(conn, "INCR", redisKey)
	if err != nil {
		return Decision{}, err
	}
	if count == 1 {
		_, _ = redisCommandInt(conn, "PEXPIRE", redisKey, strconv.FormatInt(rule.Window.Milliseconds(), 10))
	}
	if count > int64(rule.Limit) {
		pttl, _ := redisCommandInt(conn, "PTTL", redisKey)
		return Decision{Allowed: false, Limit: rule.Limit, Remaining: 0, RetryAfter: time.Duration(pttl) * time.Millisecond}, ErrLimited
	}
	return Decision{Allowed: true, Limit: rule.Limit, Remaining: rule.Limit - int(count)}, nil
}

func redisCommandInt(conn net.Conn, args ...string) (int64, error) {
	if _, err := fmt.Fprintf(conn, "*%d\r\n", len(args)); err != nil {
		return 0, err
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(arg), arg); err != nil {
			return 0, err
		}
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return 0, err
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, ":") {
		return strconv.ParseInt(strings.TrimPrefix(line, ":"), 10, 64)
	}
	if strings.HasPrefix(line, "-") {
		return 0, errors.New(strings.TrimPrefix(line, "-"))
	}
	return 0, fmt.Errorf("unexpected redis response %q", line)
}
