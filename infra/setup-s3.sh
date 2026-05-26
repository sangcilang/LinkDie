#!/usr/bin/env bash
# setup-s3.sh — Create S3/R2 bucket, apply lifecycle policy, and apply IAM policy.
# Usage: S3_ENDPOINT=... S3_BUCKET=... AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... ./setup-s3.sh

set -euo pipefail

BUCKET="${S3_BUCKET:?S3_BUCKET is required}"
ENDPOINT="${S3_ENDPOINT:-}"
REGION="${S3_REGION:-auto}"

AWS_ARGS=()
if [[ -n "$ENDPOINT" ]]; then
  AWS_ARGS+=(--endpoint-url "$ENDPOINT")
fi
AWS_ARGS+=(--region "$REGION")

echo "==> Creating bucket: $BUCKET"
aws s3api create-bucket "${AWS_ARGS[@]}" --bucket "$BUCKET" || echo "Bucket may already exist, continuing..."

echo "==> Blocking all public access"
aws s3api put-public-access-block "${AWS_ARGS[@]}" \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo "==> Disabling versioning (zero-retention requirement)"
aws s3api put-bucket-versioning "${AWS_ARGS[@]}" \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Suspended

echo "==> Applying lifecycle policy (safety-net deletion after 8 days)"
aws s3api put-bucket-lifecycle-configuration "${AWS_ARGS[@]}" \
  --bucket "$BUCKET" \
  --lifecycle-configuration file://s3-lifecycle.json

echo "==> Applying IAM policy"
# Note: For Cloudflare R2, use the R2 dashboard to apply the token policy.
# For AWS S3, apply the IAM policy to the IAM user/role used by the backend.
echo "    IAM policy is in iam-policy.json — apply it to your IAM user/role manually."
echo "    For Cloudflare R2: create an API token with the permissions in iam-policy.json."

echo "==> Done. Bucket $BUCKET is configured."
