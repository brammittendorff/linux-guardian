#!/bin/bash
set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         🛡️  Linux Guardian - Installation Script         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust is not installed."
    echo "📥 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "✅ Rust installed successfully!"
    echo
else
    echo "✅ Rust is already installed"
    echo
fi

# Build the project
echo "🔨 Building Linux Guardian in release mode..."
cargo build --release

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    echo

    # Check if we have sudo access for installation
    if command -v sudo &> /dev/null; then
        echo "📦 Installing to /usr/local/bin/linux-guardian..."
        sudo cp target/release/linux-guardian /usr/local/bin/
        echo "✅ Installation complete!"
        echo
        echo "You can now run: sudo linux-guardian"
    else
        echo "⚠️  Cannot install to /usr/local/bin (no sudo)"
        echo "Binary is at: ./target/release/linux-guardian"
        echo "Run with: sudo ./target/release/linux-guardian"
    fi

    echo
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                   Installation Complete! ✅                ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo
    echo "Quick start:"
    echo "  sudo linux-guardian                    # Fast scan"
    echo "  sudo linux-guardian --mode comprehensive  # Full scan"
    echo "  sudo linux-guardian --help             # Show all options"
    echo
else
    echo "❌ Build failed!"
    exit 1
fi
