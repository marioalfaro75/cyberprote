// Package main builds a custom OpenTelemetry Collector for Cloud Security Fabric.
package main

import (
	"fmt"
	"os"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/provider/envprovider"
	"go.opentelemetry.io/collector/confmap/provider/fileprovider"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/debugexporter"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/zpagesextension"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/batchprocessor"
	"go.opentelemetry.io/collector/processor/memorylimiterprocessor"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/otlpreceiver"

	"github.com/cloud-security-fabric/csf/exporter/agegraphexporter"
	"github.com/cloud-security-fabric/csf/processor/ocsftransformprocessor"
	"github.com/cloud-security-fabric/csf/processor/secgraphprocessor"
	awsreceiver "github.com/cloud-security-fabric/csf/receiver/awssechubreceiver"
	azurereceiver "github.com/cloud-security-fabric/csf/receiver/azuredefenderreceiver"
	gcpreceiver "github.com/cloud-security-fabric/csf/receiver/gcpsccreceiver"
	ghreceiver "github.com/cloud-security-fabric/csf/receiver/githubghasreceiver"
)

func main() {
	info := component.BuildInfo{
		Command:     "csf-collector",
		Description: "Cloud Security Fabric — Custom OpenTelemetry Collector",
		Version:     "0.1.0",
	}

	settings := otelcol.CollectorSettings{
		BuildInfo: info,
		Factories: components,
		ConfigProviderSettings: otelcol.ConfigProviderSettings{
			ResolverSettings: confmap.ResolverSettings{
				ProviderFactories: []confmap.ProviderFactory{
					fileprovider.NewFactory(),
					envprovider.NewFactory(),
				},
				DefaultScheme: "env",
			},
		},
	}

	cmd := otelcol.NewCommand(settings)
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func components() (otelcol.Factories, error) {
	var err error
	factories := otelcol.Factories{}

	// Receivers
	factories.Receivers, err = receiver.MakeFactoryMap(
		otlpreceiver.NewFactory(),
		awsreceiver.NewFactory(),
		ghreceiver.NewFactory(),
		gcpreceiver.NewFactory(),
		azurereceiver.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, fmt.Errorf("receivers: %w", err)
	}

	// Processors
	factories.Processors, err = processor.MakeFactoryMap(
		batchprocessor.NewFactory(),
		memorylimiterprocessor.NewFactory(),
		ocsftransformprocessor.NewFactory(),
		secgraphprocessor.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, fmt.Errorf("processors: %w", err)
	}

	// Exporters
	factories.Exporters, err = exporter.MakeFactoryMap(
		debugexporter.NewFactory(),
		agegraphexporter.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, fmt.Errorf("exporters: %w", err)
	}

	// Extensions
	factories.Extensions, err = extension.MakeFactoryMap(
		zpagesextension.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, fmt.Errorf("extensions: %w", err)
	}

	return factories, nil
}
