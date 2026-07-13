package observability

import (
	"log/slog"
	"os"
	"strings"
)

func NewLogger(serviceName, level string) *slog.Logger {
	handlerLevel := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		handlerLevel = slog.LevelDebug
	case "warn", "warning":
		handlerLevel = slog.LevelWarn
	case "error":
		handlerLevel = slog.LevelError
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: handlerLevel,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.MessageKey {
				attr.Key = "message"
			}
			return attr
		},
	})

	return slog.New(handler).With("service", serviceName)
}
