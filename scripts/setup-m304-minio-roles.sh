#!/usr/bin/env bash
set -euo pipefail

container="${1:-staticdeploy-test-minio}"
alias_name=staticdeploy-m304

mc() {
  docker exec "$container" /usr/bin/mc "$@"
}

mc alias set "$alias_name" http://127.0.0.1:9000 accessKeyId secretAccessKey >/dev/null

install_policy() {
  local name="$1"
  local document="$2"
  printf '%s\n' "$document" | docker exec -i "$container" sh -c "cat > /tmp/${name}.json"
  mc admin policy create "$alias_name" "$name" "/tmp/${name}.json" >/dev/null
}

install_user() {
  local user="$1"
  local secret="$2"
  local policy="$3"
  mc admin user add "$alias_name" "$user" "$secret" >/dev/null
  mc admin policy attach "$alias_name" "$policy" --user "$user" >/dev/null
}

install_policy staticdeploy-m304-control '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": ["arn:aws:s3:::m304-*/v2/quarantine/*"]
  }]
}'
install_policy staticdeploy-m304-worker '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::m304-*"],
      "Condition": {
        "StringLike": {"s3:prefix": ["v2/quarantine/*"]}
      }
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:DeleteObject"],
      "Resource": ["arn:aws:s3:::m304-*/v2/quarantine/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": [
        "arn:aws:s3:::m304-*/v2/releases/*",
        "arn:aws:s3:::m304-*/v2/routing/*"
      ]
    }
  ]
}'
install_policy staticdeploy-m304-content '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": [
      "arn:aws:s3:::m304-*/v2/releases/*",
      "arn:aws:s3:::m304-*/v2/routing/*"
    ]
  }]
}'

install_user m304-control m304-control-secret staticdeploy-m304-control
install_user m304-worker m304-worker-secret staticdeploy-m304-worker
install_user m304-content m304-content-secret staticdeploy-m304-content
