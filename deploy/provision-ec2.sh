#!/usr/bin/env bash
# Provision a single EC2 instance for the Obscura demo-ui.
# Requires: aws CLI v2, already authenticated (`aws sts get-caller-identity` works).
# Idempotent-ish: reuses the key pair / security group if they already exist.
set -euo pipefail

# ── Config (override via env) ────────────────────────────────────────────────
REGION="${REGION:-us-east-1}"
KEY_NAME="${KEY_NAME:-obscura-key}"
SG_NAME="${SG_NAME:-obscura-sg}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t3.medium}"
VOLUME_GB="${VOLUME_GB:-20}"
TAG_NAME="${TAG_NAME:-obscura-demo}"
KEY_DIR="${KEY_DIR:-$HOME/.ssh}"
KEY_PATH="$KEY_DIR/$KEY_NAME.pem"

echo "Region: $REGION   Instance: $INSTANCE_TYPE   Key: $KEY_PATH"

# ── Your public IP (for SSH + 3000 lockdown) ─────────────────────────────────
MY_IP="$(curl -s https://checkip.amazonaws.com)"
echo "Locking SSH/3000 to your IP: $MY_IP/32"

# ── Latest Ubuntu 24.04 LTS AMI (Canonical SSM public parameter) ─────────────
AMI_ID="$(aws ssm get-parameters \
  --region "$REGION" \
  --names /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query 'Parameters[0].Value' --output text)"
echo "AMI: $AMI_ID"

# ── Key pair ─────────────────────────────────────────────────────────────────
if aws ec2 describe-key-pairs --region "$REGION" --key-names "$KEY_NAME" >/dev/null 2>&1; then
  echo "Key pair '$KEY_NAME' already exists. Using existing $KEY_PATH"
  [ -f "$KEY_PATH" ] || { echo "ERROR: $KEY_PATH not found locally but key exists in AWS. Delete the AWS key or set KEY_NAME."; exit 1; }
else
  mkdir -p "$KEY_DIR"
  aws ec2 create-key-pair --region "$REGION" --key-name "$KEY_NAME" \
    --query 'KeyMaterial' --output text > "$KEY_PATH"
  chmod 400 "$KEY_PATH"
  echo "Created key pair -> $KEY_PATH"
fi

# ── Security group ───────────────────────────────────────────────────────────
VPC_ID="$(aws ec2 describe-vpcs --region "$REGION" \
  --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"

SG_ID="$(aws ec2 describe-security-groups --region "$REGION" \
  --filters Name=group-name,Values="$SG_NAME" Name=vpc-id,Values="$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"

if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
  SG_ID="$(aws ec2 create-security-group --region "$REGION" \
    --group-name "$SG_NAME" --description "Obscura demo-ui" \
    --vpc-id "$VPC_ID" --query 'GroupId' --output text)"
  echo "Created security group $SG_ID"
else
  echo "Reusing security group $SG_ID"
fi

# Rules (ignore errors if a rule already exists)
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "$MY_IP/32" 2>/dev/null || true
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 3000 --cidr "$MY_IP/32" 2>/dev/null || true
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 80 --cidr 0.0.0.0/0 2>/dev/null || true
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 443 --cidr 0.0.0.0/0 2>/dev/null || true

# ── Launch ───────────────────────────────────────────────────────────────────
INSTANCE_ID="$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$VOLUME_GB,VolumeType=gp3}" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG_NAME}]" \
  --query 'Instances[0].InstanceId' --output text)"
echo "Launched instance $INSTANCE_ID — waiting for it to run..."

aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"

PUBLIC_IP="$(aws ec2 describe-instances --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"

echo
echo "════════════════════════════════════════════════════════"
echo " Instance ready"
echo "   ID:        $INSTANCE_ID"
echo "   Public IP: $PUBLIC_IP"
echo "   SSH:       ssh -i $KEY_PATH ubuntu@$PUBLIC_IP"
echo "════════════════════════════════════════════════════════"
