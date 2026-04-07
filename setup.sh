#!/usr/bin/env bash
# =============================================================================
#  SSH Sentinel — Setup Script
#  Tested on: Amazon Linux 2, Amazon Linux 2023, Ubuntu 20.04+
# =============================================================================
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_USER="${SENTINEL_USER:-sentinel}"
PYTHON="${PYTHON:-python3}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── 1. Detect OS ──────────────────────────────────────────────────────────────
if   [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID="$ID"
elif [ -f /etc/redhat-release ]; then
  OS_ID="rhel"
else
  OS_ID="unknown"
fi
info "Detected OS: $OS_ID"

# ── 2. Install system packages ────────────────────────────────────────────────
info "Installing system packages..."
case "$OS_ID" in
  amzn|rhel|centos|fedora)
    if command -v dnf &>/dev/null; then
      sudo dnf install -y python3 python3-pip python3-devel git gcc libffi-devel openssl-devel
    else
      sudo yum install -y python3 python3-pip python3-devel git gcc libffi-devel openssl-devel
    fi
    ;;
  ubuntu|debian)
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-pip python3-dev git build-essential libffi-dev libssl-dev
    ;;
  *)
    warn "Unknown OS. Attempting to continue — ensure python3, pip3, git are installed."
    ;;
esac

# ── 3. Create sentinel user (non-root, no login shell) ────────────────────────
if ! id "$SENTINEL_USER" &>/dev/null; then
  info "Creating system user '$SENTINEL_USER'..."
  sudo useradd -r -s /sbin/nologin -d "$REPO_DIR" "$SENTINEL_USER" 2>/dev/null || \
  sudo useradd -r -s /usr/sbin/nologin -d "$REPO_DIR" "$SENTINEL_USER"
fi

# ── 4. Install Python dependencies ───────────────────────────────────────────
info "Installing Python dependencies..."
pip3 install --upgrade pip --quiet
pip3 install -r "$REPO_DIR/requirements.txt" --quiet
info "Dependencies installed."

# ── 5. Create .env if missing ────────────────────────────────────────────────
if [ ! -f "$REPO_DIR/.env" ]; then
  info "Creating .env from .env.example..."
  cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"

  # Generate a random secret key
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$SECRET/" "$REPO_DIR/.env"

  warn "IMPORTANT: Edit $REPO_DIR/.env to set DASHBOARD_PASSWORD and email settings."
fi

# ── 6. Create static/ directory ──────────────────────────────────────────────
mkdir -p "$REPO_DIR/static"

# ── 7. Set ownership ─────────────────────────────────────────────────────────
sudo chown -R "$SENTINEL_USER":"$SENTINEL_USER" "$REPO_DIR" 2>/dev/null || \
  chown -R "$USER":"$USER" "$REPO_DIR"
chmod 600 "$REPO_DIR/.env" 2>/dev/null || true

# ── 8. Install systemd services ──────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
  info "Installing systemd services..."

  # Substitute the repo directory into service files
  for SVC in sentinel.service dashboard.service; do
    sudo sed "s|/opt/ssh-sentinel|$REPO_DIR|g" "$REPO_DIR/$SVC" \
      | sudo tee "/etc/systemd/system/$SVC" > /dev/null
    sudo sed -i "s|User=sentinel|User=$SENTINEL_USER|g" "/etc/systemd/system/$SVC"
  done

  sudo systemctl daemon-reload
  sudo systemctl enable sentinel.service dashboard.service
  info "Services installed and enabled."
fi

# ── 9. Configure firewall (iptables port-forward for standard ports) ──────────
configure_firewall() {
  info "Configuring iptables port redirects..."

  # Redirect standard ports → honeypot high ports (no root needed at runtime)
  RULES=(
    "PREROUTING -t nat -p tcp --dport 21   -j REDIRECT --to-port 2121"
    "PREROUTING -t nat -p tcp --dport 23   -j REDIRECT --to-port 2323"
    "PREROUTING -t nat -p tcp --dport 25   -j REDIRECT --to-port 2525"
    "PREROUTING -t nat -p tcp --dport 3306 -j REDIRECT --to-port 3307"
    "PREROUTING -t nat -p tcp --dport 6379 -j REDIRECT --to-port 6380"
  )
  for RULE in "${RULES[@]}"; do
    sudo iptables $RULE 2>/dev/null || true
  done

  # Save rules
  if command -v iptables-save &>/dev/null; then
    sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null 2>/dev/null || true
  fi
  if command -v service &>/dev/null; then
    sudo service iptables save 2>/dev/null || true
  fi
  info "Firewall rules applied."
}

read -rp "Configure iptables port redirects (21→2121, 23→2323, etc.)? [y/N] " fw_ans
[[ "$fw_ans" =~ ^[Yy]$ ]] && configure_firewall || warn "Skipping firewall config. Run manually if needed."

# ── 10. Start services ───────────────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
  read -rp "Start services now? [y/N] " start_ans
  if [[ "$start_ans" =~ ^[Yy]$ ]]; then
    sudo systemctl start sentinel.service
    sudo systemctl start dashboard.service
    info "Services started."
    echo ""
    sudo systemctl status sentinel.service  --no-pager -l
    sudo systemctl status dashboard.service --no-pager -l
  fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  SSH Sentinel setup complete!${NC}"
echo ""
echo "  Honeypot  →  python3 main.py          (or systemctl start sentinel)"
echo "  Dashboard →  python3 app.py           (or systemctl start dashboard)"
echo "             accessible at  http://<YOUR_IP>:5000"
echo ""
echo "  Default credentials:  admin / changeme"
echo "  Edit .env to change before exposing to the internet!"
echo -e "${GREEN}============================================================${NC}"
