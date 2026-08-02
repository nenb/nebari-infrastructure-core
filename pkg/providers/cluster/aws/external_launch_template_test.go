package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nebari-dev/nebari-infrastructure-core/pkg/config"
)

func externalLaunchTemplate(id string, version int64, nestedVirtualization string) *ExternalLaunchTemplate {
	return &ExternalLaunchTemplate{
		ID:      id,
		Version: version,
		OperatorReview: ExternalLaunchTemplateReview{
			CPUOptions: ExternalLaunchTemplateCPUOptionsReview{
				NestedVirtualization: nestedVirtualization,
			},
		},
	}
}

func TestValidateExternalLaunchTemplate(t *testing.T) {
	diskSize := 100
	tests := []struct {
		name      string
		nodeGroup NodeGroup
		wantError string
	}{
		{
			name:      "omitted is backward compatible",
			nodeGroup: NodeGroup{Instance: "m7i.xlarge"},
		},
		{
			name: "eight digit ID and positive version accepted",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: externalLaunchTemplate("lt-0123abcd", 1, "enabled"),
			},
		},
		{
			name: "seventeen digit ID accepted",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: externalLaunchTemplate("lt-0123456789abcdef0", 42, "enabled"),
			},
		},
		{
			name: "empty object rejected",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: &ExternalLaunchTemplate{},
			},
			wantError: "external_launch_template.id",
		},
		{
			name: "ID only rejected",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: externalLaunchTemplate("lt-0123456789abcdef0", 0, "enabled"),
			},
			wantError: "version must be a positive integer",
		},
		{
			name: "version only rejected",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: externalLaunchTemplate("", 7, "enabled"),
			},
			wantError: "external_launch_template.id",
		},
		{
			name: "ID too short rejected",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: externalLaunchTemplate("lt-0123abc", 7, "enabled"),
			},
			wantError: "must match ^lt-[0-9a-f]{8,17}$",
		},
		{
			name: "ID too long rejected",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: externalLaunchTemplate("lt-0123456789abcdef01", 7, "enabled"),
			},
			wantError: "must match ^lt-[0-9a-f]{8,17}$",
		},
		{
			name: "uppercase ID rejected",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: externalLaunchTemplate("lt-0123456789abcdeF0", 7, "enabled"),
			},
			wantError: "external_launch_template.id",
		},
		{
			name: "zero version rejected",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: externalLaunchTemplate("lt-0123456789abcdef0", 0, "enabled"),
			},
			wantError: "version must be a positive integer",
		},
		{
			name: "negative version rejected",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: externalLaunchTemplate("lt-0123456789abcdef0", -1, "enabled"),
			},
			wantError: "version must be a positive integer",
		},
		{
			name: "missing operator review rejected",
			nodeGroup: NodeGroup{
				Instance: "m8i.2xlarge",
				ExternalLaunchTemplate: &ExternalLaunchTemplate{
					ID:      "lt-0123456789abcdef0",
					Version: 7,
				},
			},
			wantError: "nested_virtualization must be exactly \"enabled\"",
		},
		{
			name: "wrong case review rejected",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				ExternalLaunchTemplate: externalLaunchTemplate("lt-0123456789abcdef0", 7, "Enabled"),
			},
			wantError: "nested_virtualization must be exactly \"enabled\"",
		},
		{
			name: "disk size conflict rejected",
			nodeGroup: NodeGroup{
				Instance:               "m8i.2xlarge",
				DiskSize:               &diskSize,
				ExternalLaunchTemplate: externalLaunchTemplate("lt-0123456789abcdef0", 7, "enabled"),
			},
			wantError: "disk_size cannot be set with external_launch_template",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExternalLaunchTemplate(context.Background(), "cogs", tt.nodeGroup)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error %q does not contain %q", err, tt.wantError)
			}
		})
	}
}

func TestExternalLaunchTemplateVersionYAMLTypeAndAliasRejection(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{name: "$Latest alias", version: "$Latest"},
		{name: "$Default alias", version: "$Default"},
		{name: "quoted integer", version: `"7"`},
		{name: "fractional number", version: "1.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yamlConfig := fmt.Sprintf(`project_name: test
cluster:
  aws:
    region: us-west-2
    node_groups:
      cogs:
        instance: m8i.2xlarge
        external_launch_template:
          id: lt-0123456789abcdef0
          version: %s
          operator_review:
            cpu_options:
              nested_virtualization: enabled
`, tt.version)
			parsed, err := config.ParseConfigBytes([]byte(yamlConfig))
			if err != nil {
				t.Fatalf("parse generic config: %v", err)
			}
			_, err = extractAWSConfig(context.Background(), parsed.Cluster)
			if err == nil {
				t.Fatalf("expected typed AWS config to reject version %q", tt.version)
			}
			if !strings.Contains(err.Error(), "external_launch_template.version") || !strings.Contains(err.Error(), "unquoted integer") {
				t.Fatalf("error %q does not identify the invalid YAML version type", err)
			}
		})
	}
}

func TestExternalLaunchTemplateNullYAMLRejected(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "explicit null", value: "null"},
		{name: "blank value", value: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yamlConfig := fmt.Sprintf(`project_name: test
cluster:
  aws:
    region: us-west-2
    node_groups:
      cogs:
        instance: m8i.2xlarge
        external_launch_template: %s
`, tt.value)
			parsed, err := config.ParseConfigBytes([]byte(yamlConfig))
			if err != nil {
				t.Fatalf("parse generic config: %v", err)
			}
			_, err = extractAWSConfig(context.Background(), parsed.Cluster)
			if err == nil {
				t.Fatal("expected explicit empty external_launch_template to be rejected")
			}
			if !strings.Contains(err.Error(), "must be a non-empty mapping") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestExternalLaunchTemplateValidYAML(t *testing.T) {
	const yamlConfig = `project_name: test
cluster:
  aws:
    region: us-west-2
    node_groups:
      cogs:
        instance: m8i.2xlarge
        external_launch_template:
          id: lt-0123456789abcdef0
          version: 7
          operator_review:
            cpu_options:
              nested_virtualization: enabled
`
	parsed, err := config.ParseConfigBytes([]byte(yamlConfig))
	if err != nil {
		t.Fatalf("parse generic config: %v", err)
	}
	awsConfig, err := extractAWSConfig(context.Background(), parsed.Cluster)
	if err != nil {
		t.Fatalf("extract typed AWS config: %v", err)
	}
	got := awsConfig.NodeGroups["cogs"].ExternalLaunchTemplate
	want := externalLaunchTemplate("lt-0123456789abcdef0", 7, "enabled")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("external launch template = %#v, want %#v", got, want)
	}
}

func TestExternalLaunchTemplateTFVarsJSONPreservation(t *testing.T) {
	launchTemplate := externalLaunchTemplate("lt-0123456789abcdef0", 7, "enabled")
	snapshot := *launchTemplate
	cfg := Config{
		Region: "us-west-2",
		NodeGroups: map[string]NodeGroup{
			"cogs": {
				Instance:               "m8i.2xlarge",
				MinNodes:               1,
				MaxNodes:               3,
				ExternalLaunchTemplate: launchTemplate,
			},
			"standard": {Instance: "m7i.xlarge", MinNodes: 1, MaxNodes: 2},
		},
	}

	vars := cfg.toTFVars("test", "", nil)
	got := vars.NodeGroups["cogs"].ExternalLaunchTemplate
	if got == nil {
		t.Fatal("external launch template was dropped from TFVars")
	}
	if !reflect.DeepEqual(*got, snapshot) {
		t.Fatalf("TFVars external launch template = %#v, want %#v", *got, snapshot)
	}
	if !reflect.DeepEqual(*launchTemplate, snapshot) {
		t.Fatalf("toTFVars mutated caller config: got %#v, want %#v", *launchTemplate, snapshot)
	}

	encoded, err := json.Marshal(vars)
	if err != nil {
		t.Fatalf("marshal TFVars: %v", err)
	}
	var document struct {
		NodeGroups map[string]struct {
			ExternalLaunchTemplate json.RawMessage `json:"external_launch_template"`
		} `json:"node_groups"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode TFVars JSON: %v", err)
	}
	const expected = `{"id":"lt-0123456789abcdef0","version":7,"operator_review":{"cpu_options":{"nested_virtualization":"enabled"}}}`
	if got := string(document.NodeGroups["cogs"].ExternalLaunchTemplate); got != expected {
		t.Fatalf("external launch template JSON = %s, want %s", got, expected)
	}
	if got := document.NodeGroups["standard"].ExternalLaunchTemplate; len(got) != 0 {
		t.Fatalf("standard node group unexpectedly emitted external_launch_template: %s", got)
	}
}
