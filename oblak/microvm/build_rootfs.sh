#!/usr/bin/env bash
# Build a minimal Alpine Linux + Python 3 rootfs image for Firecracker.
# Requires: docker, dd, mkfs.ext4, mount (run as root or with sudo).
#
# Output: rootfs.ext4 (place at OBLAK_ROOTFS_PATH, default /var/lib/oblak/rootfs.ext4)
# Companion kernel: download vmlinux from the Firecracker releases page and place at
# OBLAK_KERNEL_PATH (default /var/lib/oblak/vmlinux).

set -euo pipefail

ROOTFS_SIZE_MB=512
OUTPUT="${1:-rootfs.ext4}"
CONTAINER_NAME="oblak-rootfs-builder-$$"

echo "[1/5] Creating empty ext4 image (${ROOTFS_SIZE_MB} MB)..."
dd if=/dev/zero of="$OUTPUT" bs=1M count="$ROOTFS_SIZE_MB" status=none
mkfs.ext4 -F -L oblak-rootfs "$OUTPUT"

MNT=$(mktemp -d)
echo "[2/5] Mounting image at $MNT..."
mount -o loop "$OUTPUT" "$MNT"

echo "[3/5] Bootstrapping Alpine Linux via Docker..."
docker run --name "$CONTAINER_NAME" \
    alpine:3.19 \
    sh -c "apk add --no-cache python3 py3-pip util-linux && pip3 install --no-cache-dir --break-system-packages pip" \
    || true

docker export "$CONTAINER_NAME" | tar -xf - -C "$MNT"
docker rm "$CONTAINER_NAME"

echo "[4/5] Installing guest agent..."
AGENT_DIR="$MNT/microvm"
mkdir -p "$AGENT_DIR"
cp "$(dirname "$0")/agent.py" "$AGENT_DIR/agent.py"
cp "$(dirname "$0")/runner.py" "$AGENT_DIR/runner.py"
touch "$AGENT_DIR/__init__.py"

# Configure agent.py as /sbin/init
cat > "$MNT/sbin/oblak-init" <<'EOF'
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/")
from microvm.agent import main
main()
EOF
chmod +x "$MNT/sbin/oblak-init"
ln -sf /sbin/oblak-init "$MNT/sbin/init"

echo "[5/5] Unmounting..."
umount "$MNT"
rmdir "$MNT"

echo "Done: $OUTPUT"
echo ""
echo "Next steps:"
echo "  sudo cp $OUTPUT /var/lib/oblak/rootfs.ext4"
echo "  Download vmlinux from https://github.com/firecracker-microvm/firecracker/releases"
echo "  sudo cp vmlinux /var/lib/oblak/vmlinux"
echo "  sudo useradd -r -u 65533 -g 65533 -s /sbin/nologin oblak-vm"
