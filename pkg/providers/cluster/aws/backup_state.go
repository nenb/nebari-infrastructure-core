package aws

import (
	"github.com/nebari-dev/nebari-infrastructure-core/pkg/providers/cluster"
)

// backupStateModuleCommit is the exact terraform-aws-eks-cluster commit whose
// source was reviewed for the addresses in backupStateAddrs. The addresses were
// originally verified with `tofu graph` at v0.7.0. Commit c3017c0 is based on
// v0.7.0 and changes only variables, locals, an output, documentation, and the
// static-test harness/CI; source review confirmed that it does not change
// Longhorn resources or their module nesting. No tofu graph was run for this
// commit. TestBackupStateAddrsBoundToPinnedModuleCommit makes any later pin
// change fail until its effect on these safety-critical addresses is reviewed.
const backupStateModuleCommit = "c3017c0e15b538cd4e04c0786809a861ea82c621"

// backupStateAddrs returns the Terraform state addresses for a NIC-provisioned
// Longhorn backup S3 bucket that must be removed from state before `tofu
// destroy` so the bucket and its backups survive teardown. It returns nil when
// there is nothing to retain: no spec (spec == nil), a spec that did not create
// the bucket (spec.Create == false — e.g. a keyless Pod Identity association
// scoped to a pre-existing bucket, or an external bucket), or retain_on_destroy
// is off (spec.ForceDestroy == true), in which case the bucket is destroyed
// normally.
//
// Addresses are ordered dependents-first so a removal that processes them in
// order never references an already-removed parent.
func backupStateAddrs(spec *cluster.BackupBucketSpec) []string {
	if spec == nil || !spec.Create || spec.ForceDestroy {
		return nil
	}
	// These resources live in the eks_cluster module's own longhorn-backup
	// submodule, so the address is nested twice: module.eks_cluster (the shim's
	// call) then module.longhorn_backup (the module's call). Both the submodule
	// call and the resources inside it are count-gated, hence the two [0]
	// indices; if either ever moves to `for_each`, these addresses (e.g. [0] ->
	// ["<key>"]) must be updated to match.
	//
	// Bound to terraform-aws-eks-cluster backupStateModuleCommit; the test tying
	// that constant to templates/main.tf forces review on every module pin change.
	return []string{
		"module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket_public_access_block.this[0]",
		"module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket_server_side_encryption_configuration.this[0]",
		"module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket_lifecycle_configuration.this[0]",
		"module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket_versioning.this[0]",
		"module.eks_cluster.module.longhorn_backup[0].aws_s3_bucket.this[0]",
	}
}
