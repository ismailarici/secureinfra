#!/usr/bin/env bash
# Run Prowler against AWS via Docker.
# Reads AWS credentials from environment variables or ~/.aws/credentials.
# Output lands in outputs/prowler/.
#
# Usage:
#   export AWS_PROFILE=my-profile
#   bash scripts/run_prowler.sh
#
# Requires: Docker, valid AWS credentials

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config/config.yaml}"
OUTPUT_DIR="${OUTPUT_DIR:-outputs/prowler}"
IMAGE="${PROWLER_IMAGE:-public.ecr.aws/prowler-cloud/prowler:latest}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
OUTPUT_FILENAME="prowler_output"

mkdir -p "$OUTPUT_DIR"

echo "[run_prowler] Pulling Prowler image: $IMAGE"
docker pull "$IMAGE"

echo "[run_prowler] Running Prowler scan (region: $REGION)"
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION="$REGION" \
  -v "$HOME/.aws:/root/.aws:ro" \
  -v "$(pwd)/$OUTPUT_DIR:/tmp/prowler-output" \
  "$IMAGE" aws \
    --output-formats json \
    --output-directory /tmp/prowler-output \
    --output-filename "$OUTPUT_FILENAME" \
    --severity critical high medium \
    || true   # Prowler exits 3 when findings exist — not a failure

OUTPUT_PATH="$OUTPUT_DIR/${OUTPUT_FILENAME}.json"

if [ -f "$OUTPUT_PATH" ]; then
  FINDING_COUNT=$(python3 -c "import json; d=json.load(open('$OUTPUT_PATH')); print(len([x for x in d if x.get('Status')=='FAIL']))" 2>/dev/null || echo "unknown")
  echo "[run_prowler] Complete — $FINDING_COUNT FAIL findings written to $OUTPUT_PATH"
else
  echo "[run_prowler] WARNING: output file not found at $OUTPUT_PATH"
  exit 1
fi
