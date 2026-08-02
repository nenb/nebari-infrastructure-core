package nic

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nebari-dev/nebari-infrastructure-core/pkg/config"
	"github.com/nebari-dev/nebari-infrastructure-core/pkg/providers/cluster"
	"github.com/nebari-dev/nebari-infrastructure-core/pkg/providers/cluster/aws"
	"github.com/nebari-dev/nebari-infrastructure-core/pkg/registry"
)

type offlineValidationFakeProvider struct {
	offlineDelegate cluster.OfflineValidator
	offlineCalls    int
	validateCalls   int
	deployCalls     int
	infraCalls      int
}

func (p *offlineValidationFakeProvider) Name() string { return "test" }

func (p *offlineValidationFakeProvider) ValidateOffline(ctx context.Context, projectName string, clusterConfig *config.ClusterConfig) error {
	p.offlineCalls++
	return p.offlineDelegate.ValidateOffline(ctx, projectName, clusterConfig)
}

func (p *offlineValidationFakeProvider) Validate(context.Context, string, *config.ClusterConfig) error {
	p.validateCalls++
	return fmt.Errorf("online validation must not be called")
}

func (p *offlineValidationFakeProvider) Deploy(context.Context, string, *config.ClusterConfig, cluster.DeployOptions) error {
	p.deployCalls++
	return fmt.Errorf("deploy must not be called")
}

func (p *offlineValidationFakeProvider) Destroy(context.Context, string, *config.ClusterConfig, cluster.DestroyOptions) error {
	return fmt.Errorf("destroy not implemented")
}

func (p *offlineValidationFakeProvider) GetKubeconfig(context.Context, string, *config.ClusterConfig) ([]byte, error) {
	return nil, fmt.Errorf("kubeconfig not implemented")
}

func (p *offlineValidationFakeProvider) Summary(*config.ClusterConfig) map[string]string { return nil }

func (p *offlineValidationFakeProvider) InfraSettings(*config.ClusterConfig) cluster.InfraSettings {
	p.infraCalls++
	return cluster.InfraSettings{StorageClass: "longhorn"}
}

func TestClientOfflineValidationPrecedesProviderActivity(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(nodeGroup, external map[string]any)
		wantInErr string
	}{
		{
			name: "malformed launch template ID",
			mutate: func(_ map[string]any, external map[string]any) {
				external["id"] = "lt-not-an-id"
			},
			wantInErr: "external_launch_template.id",
		},
		{
			name: "zero launch template version",
			mutate: func(_ map[string]any, external map[string]any) {
				external["version"] = 0
			},
			wantInErr: "version must be a positive integer",
		},
		{
			name: "wrong-case operator review",
			mutate: func(_ map[string]any, external map[string]any) {
				external["operator_review"] = map[string]any{
					"cpu_options": map[string]any{"nested_virtualization": "Enabled"},
				}
			},
			wantInErr: "nested_virtualization must be exactly \"enabled\"",
		},
		{
			name: "disk size conflict",
			mutate: func(nodeGroup, _ map[string]any) {
				nodeGroup["disk_size"] = 100
			},
			wantInErr: "disk_size cannot be set with external_launch_template",
		},
	}

	operations := []struct {
		name         string
		providerName string
		newClient    func(context.Context, *testing.T) (*Client, *offlineValidationFakeProvider)
		run          func(context.Context, *Client, *config.NebariConfig) error
	}{
		{
			name:         "Client.Validate with registered AWS provider",
			providerName: "aws",
			newClient: func(ctx context.Context, t *testing.T) (*Client, *offlineValidationFakeProvider) {
				client, err := NewClient(ctx)
				if err != nil {
					t.Fatalf("NewClient: %v", err)
				}
				return client, nil
			},
			run: func(ctx context.Context, client *Client, cfg *config.NebariConfig) error {
				return client.Validate(ctx, cfg)
			},
		},
		{
			name:         "Client.Deploy fake-provider preflight",
			providerName: "test",
			newClient: func(ctx context.Context, t *testing.T) (*Client, *offlineValidationFakeProvider) {
				fake := &offlineValidationFakeProvider{offlineDelegate: aws.NewProvider()}
				reg := registry.NewRegistry()
				if err := reg.ClusterProviders.Register(ctx, "test", fake); err != nil {
					t.Fatalf("register fake provider: %v", err)
				}
				return &Client{registry: reg}, fake
			},
			run: func(ctx context.Context, client *Client, cfg *config.NebariConfig) error {
				_, err := client.Deploy(ctx, cfg, DeployOptions{DryRun: true})
				return err
			},
		},
	}

	for _, operation := range operations {
		for _, tt := range tests {
			t.Run(operation.name+"/"+tt.name, func(t *testing.T) {
				external := map[string]any{
					"id":      "lt-0123456789abcdef0",
					"version": 7,
					"operator_review": map[string]any{
						"cpu_options": map[string]any{"nested_virtualization": "enabled"},
					},
				}
				nodeGroup := map[string]any{
					"instance":                 "m8i.2xlarge",
					"min_nodes":                1,
					"max_nodes":                1,
					"external_launch_template": external,
				}
				tt.mutate(nodeGroup, external)

				cfg := &config.NebariConfig{
					ProjectName: "test-project",
					Cluster: &config.ClusterConfig{Providers: map[string]any{
						operation.providerName: map[string]any{
							"region":      "us-west-2",
							"node_groups": map[string]any{"cogs": nodeGroup},
						},
					}},
				}

				ctx := context.Background()
				client, fake := operation.newClient(ctx, t)
				err := operation.run(ctx, client, cfg)
				if err == nil {
					t.Fatalf("expected offline validation error containing %q", tt.wantInErr)
				}
				if !strings.Contains(err.Error(), tt.wantInErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantInErr)
				}
				if fake != nil {
					if fake.offlineCalls != 1 {
						t.Fatalf("ValidateOffline calls = %d, want 1", fake.offlineCalls)
					}
					if fake.validateCalls != 0 || fake.deployCalls != 0 || fake.infraCalls != 0 {
						t.Fatalf("provider activity occurred after failed preflight: Validate=%d Deploy=%d InfraSettings=%d",
							fake.validateCalls, fake.deployCalls, fake.infraCalls)
					}
				}
			})
		}
	}
}
