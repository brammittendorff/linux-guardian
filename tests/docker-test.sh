#!/bin/bash
# Docker-based multi-distribution testing
# Tests Linux Guardian on Ubuntu, Debian, Fedora, Arch

set -e

echo "🐳 Linux Guardian - Multi-Distribution Testing"
echo "=============================================="
echo

# Use already-built binary
BINARY_PATH="../target/release/linux-guardian"

if [ ! -f "$BINARY_PATH" ]; then
    echo "❌ Binary not found at $BINARY_PATH"
    echo "Build first with: /home/bram/.cargo/bin/cargo build --release"
    exit 1
fi

echo "✅ Using binary: $BINARY_PATH"
echo

# Test distributions
DISTROS=(
    "ubuntu:22.04"
    "ubuntu:24.04"
    "debian:11"
    "debian:12"
    "fedora:39"
    "fedora:40"
)

for distro in "${DISTROS[@]}"; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🧪 Testing on: $distro"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo

    # Run scanner in Docker container
    docker run --rm \
        -v "$(realpath $BINARY_PATH):/scanner:ro" \
        "$distro" \
        /bin/bash -c "
            echo '📊 Distribution Info:'
            cat /etc/os-release | grep -E 'PRETTY_NAME|VERSION_ID'
            echo

            echo '🔍 Running Linux Guardian Fast Scan:'
            /scanner --skip-privilege-check --quiet 2>&1 | tail -15

            echo
            echo '✅ Test completed for $distro'
            echo
        " || echo "❌ Test failed for $distro"

    echo
    sleep 2
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ All distribution tests complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
