package aws

import (
	"regexp"
	"testing"

	"github.com/nebari-dev/nebari-infrastructure-core/pkg/providers/cluster"
)

var (
	eksClusterModuleCommitPin = regexp.MustCompile(`source\s*=\s*"git::https://github\.com/nenb/terraform-aws-eks-cluster\.git\?ref=([0-9a-f]{40})"`)
	moduleVersionConstraint   = regexp.MustCompile(`(?m)^\s*version\s*=`)
)

func TestEKSClusterModulePinnedToFullCommit(t *testing.T) {
	mainTF, err := tofuTemplates.ReadFile("templates/main.tf")
	if err != nil {
		t.Fatalf("read embedded templates/main.tf: %v", err)
	}
	matches := eksClusterModuleCommitPin.FindSubmatch(mainTF)
	if matches == nil {
		t.Fatal("templates/main.tf must pin the forked terraform-aws-eks-cluster module with an immutable full Git SHA")
	}
	if got := string(matches[1]); got != backupStateModuleCommit {
		t.Fatalf("module source pins %s, want reviewed commit %s", got, backupStateModuleCommit)
	}
	if moduleVersionConstraint.Match(mainTF) {
		t.Fatal("Git module source must not also use a registry version constraint")
	}
}

// TestBackupStateAddrsBoundToPinnedModuleCommit fails on every module pin
// change. The addresses were graph-verified at v0.7.0; for the current commit,
// the v0.7.0 source diff was reviewed and contains no Longhorn resource or
// module-nesting changes. No graph execution is claimed for the fork commit.
func TestBackupStateAddrsBoundToPinnedModuleCommit(t *testing.T) {
	mainTF, err := tofuTemplates.ReadFile("templates/main.tf")
	if err != nil {
		t.Fatalf("read embedded templates/main.tf: %v", err)
	}
	matches := eksClusterModuleCommitPin.FindSubmatch(mainTF)
	if matches == nil {
		t.Fatal("templates/main.tf does not contain the expected full-SHA module source; review backupStateAddrs before changing the pin")
	}
	if got := string(matches[1]); got != backupStateModuleCommit {
		t.Fatalf("module source pins %s but backupStateAddrs are source-reviewed against %s; review the module diff and update backupStateModuleCommit", got, backupStateModuleCommit)
	}
}

func TestBackupStateAddrs(t *testing.T) {
	tests := []struct {
		name string
		spec *cluster.BackupBucketSpec
		want []string
	}{
		{
			name: "nil spec returns no addresses",
			spec: nil,
			want: nil,
		},
		{
			name: "force destroy returns no addresses (delete on destroy)",
			spec: &cluster.BackupBucketSpec{Create: true, ForceDestroy: true},
			want: nil,
		},
		{
			name: "create false returns no addresses (pod-identity only / external bucket)",
			spec: &cluster.BackupBucketSpec{Create: false, ForceDestroy: false, PodIdentity: true},
			want: nil,
		},
		{
			name: "retain returns all dependent addresses, dependents first",
			spec: &cluster.BackupBucketSpec{Create: true, ForceDestroy: false},
			want: []string{
				"module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket_public_access_block.this[0]",
				"module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket_server_side_encryption_configuration.this[0]",
				"module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket_lifecycle_configuration.this[0]",
				"module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket_versioning.this[0]",
				"module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket.this[0]",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := backupStateAddrs(tt.spec)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("addr[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
			// The bucket itself must always be last so its dependents are
			// removed first.
			if len(got) > 0 && got[len(got)-1] != "module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket.this[0]" {
				t.Fatalf("expected bucket address last, got %q", got[len(got)-1])
			}
		})
	}
}
