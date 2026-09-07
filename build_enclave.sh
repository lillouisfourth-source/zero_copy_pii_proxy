#!/bin/bash
# build_enclave.sh - Build Nitro Enclave Image from Docker
#
# This script converts the Docker image into an AWS Nitro Enclave Image (.eif)
# that can be launched on EC2 with hardware-level zero-trust isolation.
#
# Prerequisites:
#   1. Docker installed and running
#   2. AWS Nitro CLI installed: pip install aws-nitro-cli
#   3. Running on Amazon Linux 2, Ubuntu, or compatible Linux distribution
#   4. AWS EC2 instance with Nitro Enclave support (c5.xlarge or larger)
#
# Usage:
#   ./build_enclave.sh [--docker-tag TAG] [--output-file PATH] [--no-docker]
#
# Example:
#   ./build_enclave.sh --docker-tag zero_copy_pii_proxy:latest --output-file proxy.eif

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCKER_TAG="${DOCKER_TAG:-zero_copy_pii_proxy:latest}"
OUTPUT_FILE="${OUTPUT_FILE:-proxy.eif}"
SKIP_DOCKER_BUILD="${SKIP_DOCKER_BUILD:-false}"
ENCLAVE_CPU_COUNT="${ENCLAVE_CPU_COUNT:-4}"
ENCLAVE_MEMORY="${ENCLAVE_MEMORY:-2048}"

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

# ============================================================================
# Phase 1: Verify Prerequisites
# ============================================================================

verify_prerequisites() {
    log_info "Phase 1: Verifying prerequisites..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        log_info "Install Docker: https://docs.docker.com/engine/install/"
        exit 1
    fi
    log_success "Docker found: $(docker --version)"

    # Check Nitro CLI
    if ! command -v nitro-cli &> /dev/null; then
        log_error "AWS Nitro CLI is not installed or not in PATH"
        log_info "Install Nitro CLI: pip install aws-nitro-cli"
        exit 1
    fi
    log_success "Nitro CLI found: $(nitro-cli --version 2>/dev/null || echo 'installed')"

    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        log_info "Start Docker: sudo systemctl start docker (on Linux)"
        exit 1
    fi
    log_success "Docker daemon is running"

    # Check Linux
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        log_warning "VSOCK support is Linux-only. Enclave image (.eif) requires Linux host."
        log_info "Run this script on Amazon Linux 2, Ubuntu, or compatible Linux EC2 instance"
    fi

    log_success "Prerequisites verified"
    echo ""
}

# ============================================================================
# Phase 2: Build Docker Image
# ============================================================================

build_docker_image() {
    if [[ "$SKIP_DOCKER_BUILD" == "true" ]]; then
        log_warning "Skipping Docker build (--no-docker flag set)"
        return
    fi

    log_info "Phase 2: Building Docker image..."
    log_info "Tag: $DOCKER_TAG"

    if ! docker build -t "$DOCKER_TAG" . ; then
        log_error "Docker build failed"
        exit 1
    fi

    # Verify image was created
    if docker image inspect "$DOCKER_TAG" &> /dev/null; then
        IMAGE_SIZE=$(docker image inspect "$DOCKER_TAG" --format='{{.Size}}' | numfmt --to=iec 2>/dev/null || echo "unknown")
        log_success "Docker image built successfully"
        log_info "Image size: $IMAGE_SIZE"
    else
        log_error "Docker image was not created"
        exit 1
    fi

    echo ""
}

# ============================================================================
# Phase 3: Build Nitro Enclave Image
# ============================================================================

build_enclave_image() {
    log_info "Phase 3: Building Nitro Enclave Image (.eif)..."
    log_info "Input Docker image: $DOCKER_TAG"
    log_info "Output file: $OUTPUT_FILE"

    # Remove existing .eif file if present
    if [[ -f "$OUTPUT_FILE" ]]; then
        log_warning "Removing existing $OUTPUT_FILE"
        rm -f "$OUTPUT_FILE"
    fi

    # Build enclave image
    if ! nitro-cli build-enclave \
        --docker-uri "$DOCKER_TAG" \
        --output-file "$OUTPUT_FILE" \
        2>&1 | tee -a enclave_build.log; then
        log_error "Nitro enclave build failed. See enclave_build.log for details."
        exit 1
    fi

    # Verify .eif file was created
    if [[ ! -f "$OUTPUT_FILE" ]]; then
        log_error "Enclave image (.eif) file was not created"
        exit 1
    fi

    log_success "Enclave image built successfully"

    # Show file details
    FILE_SIZE=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat -c%s "$OUTPUT_FILE" 2>/dev/null || echo "unknown")
    log_info "Enclave image size: $(echo "$FILE_SIZE" | numfmt --to=iec 2>/dev/null || echo "$FILE_SIZE bytes")"

    echo ""
}

# ============================================================================
# Phase 4: Compute Cryptographic Hashes
# ============================================================================

compute_hashes() {
    log_info "Phase 4: Computing cryptographic hashes..."

    # Docker image hash
    if docker image inspect "$DOCKER_TAG" &> /dev/null; then
        DOCKER_IMAGE_SHA=$(docker image inspect "$DOCKER_TAG" --format='{{.ID}}' | cut -d: -f2)
        log_info "Docker image SHA256: $DOCKER_IMAGE_SHA"
    fi

    # Enclave image hash
    if [[ -f "$OUTPUT_FILE" ]]; then
        EIF_SHA=$(sha256sum "$OUTPUT_FILE" | cut -d' ' -f1)
        log_success "Enclave image SHA256: $EIF_SHA"

        # Save hash to file for verification
        echo "$EIF_SHA  $OUTPUT_FILE" > "${OUTPUT_FILE}.sha256"
        log_info "Hash saved to ${OUTPUT_FILE}.sha256"
    fi

    echo ""
}

# ============================================================================
# Phase 5: Generate Launch Instructions
# ============================================================================

generate_launch_instructions() {
    log_info "Phase 5: Generating launch instructions..."

    INSTRUCTIONS_FILE="LAUNCH_ENCLAVE.sh"

    cat > "$INSTRUCTIONS_FILE" << 'LAUNCH_SCRIPT'
#!/bin/bash
# LAUNCH_ENCLAVE.sh - Launch Nitro Enclave on EC2 Instance
#
# This script launches the pre-built enclave image on an EC2 instance
# with Nitro Enclave support.
#
# Prerequisites:
#   - Running on EC2 instance with Nitro Enclave support (c5.xlarge+)
#   - AWS Nitro CLI installed
#   - proxy.eif file in current directory
#
# Usage:
#   sudo ./LAUNCH_ENCLAVE.sh [--enclave-cid CID] [--cpu-count N] [--memory MB]

set -euo pipefail

EIF_FILE="${1:-proxy.eif}"
ENCLAVE_CID="${ENCLAVE_CID:-42}"
ENCLAVE_CPU="${ENCLAVE_CPU:-4}"
ENCLAVE_MEMORY="${ENCLAVE_MEMORY:-2048}"

if [[ ! -f "$EIF_FILE" ]]; then
    echo "Error: Enclave image not found: $EIF_FILE"
    exit 1
fi

echo "Launching Nitro Enclave..."
echo "  Image: $EIF_FILE"
echo "  CID: $ENCLAVE_CID"
echo "  CPUs: $ENCLAVE_CPU"
echo "  Memory: ${ENCLAVE_MEMORY}MB"
echo ""

# Launch enclave
sudo nitro-cli run-enclave \
    --enclave-image-format eif \
    --eif-path "$EIF_FILE" \
    --cpu-count "$ENCLAVE_CPU" \
    --memory "$ENCLAVE_MEMORY" \
    --enclave-cid "$ENCLAVE_CID" \
    --debug-mode

echo "Enclave launched successfully!"
echo ""
echo "Next steps:"
echo "  1. Verify enclave status:"
echo "     sudo nitro-cli describe-enclaves"
echo ""
echo "  2. Start VSOCK bridge (run on host, outside enclave):"
echo "     ./target/release/vsock_host_bridge --enclave-cid $ENCLAVE_CID"
echo ""
echo "  3. Test proxy (from another terminal):"
echo "     curl -X POST http://localhost:3000/v1/chat/completions -H 'Content-Type: application/json' ..."
echo ""
echo "  4. View enclave logs:"
echo "     sudo nitro-cli console --enclave-id <ENCLAVE_ID>"
echo ""
echo "  5. Terminate enclave when done:"
echo "     sudo nitro-cli terminate-enclave --enclave-id <ENCLAVE_ID>"

LAUNCH_SCRIPT

    chmod +x "$INSTRUCTIONS_FILE"
    log_success "Launch script generated: $INSTRUCTIONS_FILE"

    echo ""
}

# ============================================================================
# Phase 6: Attestation Verification Instructions
# ============================================================================

generate_attestation_instructions() {
    log_info "Phase 6: Generating attestation verification guide..."

    ATTESTATION_FILE="VERIFY_ATTESTATION.md"

    cat > "$ATTESTATION_FILE" << 'ATTESTATION_DOC'
# Verifying Nitro Enclave Attestation

## Overview

AWS Nitro Enclaves use cryptographic attestation to prove:
- Code integrity (enclave image hash)
- Platform identity (EC2 instance)
- Execution environment (AWS infrastructure)

## Prerequisites

After launching the enclave, retrieve the attestation document:

```bash
# On the host EC2 instance
sudo nitro-cli describe-enclaves
# Note the ENCLAVE_ID from the output

# Inside the enclave (via console), or from the parent via attestation API
# The enclave can request an attestation document via:
curl -s http://169.254.169.254/latest/api/aws/attestation-document
```

## Verify Attestation Document

### 1. Extract Certificate Chain

```bash
aws ec2-instance-connect send-command \
    --instance-ids i-xxxxxxxx \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["nitro-cli describe-enclaves | jq ."]'
```

### 2. Verify Platform Configuration Register (PCR)

Nitro Enclaves use PCRs to cryptographically verify:
- **PCR0**: Enclave image measurements (code + firmware)
- **PCR1**: IAM policy applied to enclave
- **PCR2**: Parent EC2 instance identity
- **PCR8**: Custom data/attestation document

Verify PCR0 against a known value:

```bash
# Known PCR0 (replace with actual value from your build)
EXPECTED_PCR0="deadbeef..."
ACTUAL_PCR0=$(jq -r '.pcr0' attestation.json)

if [[ "$EXPECTED_PCR0" == "$ACTUAL_PCR0" ]]; then
    echo "✓ PCR0 matches (enclave code is authentic)"
else
    echo "✗ PCR0 mismatch (possible tampering)"
    exit 1
fi
```

### 3. Verify Certificate Signature

```bash
# Extract certificate from attestation document
openssl asn1parse -in attestation.pem -i

# Verify chain to AWS root CA
openssl verify -CAfile aws-nitro-root-ca.pem attestation.pem
```

## Security Implications

✓ **Attestation Verified**: Enclave runs unmodified code on genuine AWS Nitro hardware
✗ **Attestation Failed**: Enclave code or environment has been tampered with

## Further Reading

- [AWS Nitro Enclaves Documentation](https://docs.aws.amazon.com/enclaves/latest/user/attestation.html)
- [Verifying Attestation](https://docs.aws.amazon.com/enclaves/latest/user/verify-attestation.html)

ATTESTATION_DOC

    log_success "Attestation guide generated: $ATTESTATION_FILE"

    echo ""
}

# ============================================================================
# Phase 7: Summary
# ============================================================================

print_summary() {
    log_info "Build Summary"
    echo "============================================"
    log_success "Phase 1: Prerequisites verified"
    log_success "Phase 2: Docker image built"
    log_success "Phase 3: Nitro Enclave image built"
    log_success "Phase 4: Cryptographic hashes computed"
    log_success "Phase 5: Launch instructions generated"
    log_success "Phase 6: Attestation guide generated"
    echo ""

    log_info "Generated Artifacts"
    echo "============================================"
    echo "  Enclave image:  $OUTPUT_FILE"
    echo "  Image hash:     ${OUTPUT_FILE}.sha256"
    echo "  Launch script:  LAUNCH_ENCLAVE.sh"
    echo "  Attestation:    VERIFY_ATTESTATION.md"
    echo "  Build log:      enclave_build.log"
    echo ""

    log_info "Next Steps"
    echo "============================================"
    echo "  1. Transfer .eif file to EC2 instance (if built on different host)"
    echo "  2. SSH to EC2 instance with Nitro Enclave support"
    echo "  3. Run: sudo ./LAUNCH_ENCLAVE.sh proxy.eif"
    echo "  4. Verify enclave: sudo nitro-cli describe-enclaves"
    echo "  5. Start VSOCK bridge: ./target/release/vsock_host_bridge"
    echo "  6. Test proxy endpoint (see README.md for examples)"
    echo ""

    log_success "Enclave build complete!"
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  AWS Nitro Enclave Build Pipeline                          ║"
    echo "║  Zero-Copy PII Proxy - Hardware-Level Zero-Trust Isolation ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --docker-tag)
                DOCKER_TAG="$2"
                shift 2
                ;;
            --output-file)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --no-docker)
                SKIP_DOCKER_BUILD="true"
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --docker-tag TAG        Docker image tag (default: zero_copy_pii_proxy:latest)"
                echo "  --output-file FILE      Output .eif filename (default: proxy.eif)"
                echo "  --no-docker             Skip Docker image build (assume already built)"
                echo "  --help                  Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Execute build phases
    verify_prerequisites
    build_docker_image
    build_enclave_image
    compute_hashes
    generate_launch_instructions
    generate_attestation_instructions
    print_summary
}

# Run main function
main "$@"
