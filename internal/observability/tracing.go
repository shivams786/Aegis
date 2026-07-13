package observability

import (
	"context"
	"log/slog"

	"github.com/aegis/aegis/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func InitTracer(ctx context.Context, cfg config.Config, logger *slog.Logger) (func(context.Context) error, error) {
	res := resource.NewSchemaless(
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("deployment.environment", cfg.Environment),
	)

	options := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
	}

	if cfg.OTELEndpoint != "" {
		exporter, err := otlptracegrpc.New(
			ctx,
			otlptracegrpc.WithEndpoint(cfg.OTELEndpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, err
		}
		options = append(options, sdktrace.WithBatcher(exporter))
		logger.Info("otel trace exporter enabled", "endpoint", cfg.OTELEndpoint)
	} else {
		logger.Info("otel trace exporter disabled; spans remain process-local")
	}

	provider := sdktrace.NewTracerProvider(options...)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}
