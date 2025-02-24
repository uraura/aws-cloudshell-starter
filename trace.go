package main

import (
	"context"
	"log"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
)

func NewExporter() (sdktrace.SpanExporter, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	return jaeger.New(
		jaeger.WithCollectorEndpoint(
			jaeger.WithEndpoint(endpoint),
		),
	)

	//return stdouttrace.New(
	//	stdouttrace.WithPrettyPrint(),
	//	stdouttrace.WithWriter(os.Stderr),
	//)
}

func NewResource(name, version string) *resource.Resource {
	return resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(name),
		semconv.ServiceVersionKey.String(version),
	)
}

func SetupTraceProvider(shutdownTimeout time.Duration) (func(), error) {
	exporter, err := NewExporter()
	if err != nil {
		return nil, err
	}

	reource := NewResource("aws-cloudshell", "1.0.0")
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(reource),
	)
	otel.SetTracerProvider(tracerProvider)

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := tracerProvider.Shutdown(ctx); err != nil {
			log.Printf("Failed to shutdown tracer provider: %v", err)
		}
	}
	return cleanup, nil
}

var tracer = otel.Tracer("aws-cloudshell")

func makeSpan(ctx context.Context, name string, fn func() error) error {
	ctx, span := tracer.Start(ctx, name)
	defer span.End()

	return fn()
}
