#!/bin/bash

# Set installation path
INSTALL_DIR="/opt/VTScanX"
VENV_DIR="$INSTALL_DIR/venv"
BIN_PATH="/usr/local/bin/vtscanx"

# Clone repo
sudo git clone https://github.com/abhishek-kadavala/VTScanX.git "$INSTALL_DIR" || {
    echo "[!] Failed to clone repo."
    exit 1
}

# Create virtual environment
sudo apt update && sudo apt install -y python3-venv
python3 -m venv "$VENV_DIR"

# Activate and install requirements
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" || {
    echo "[!] Failed to install dependencies."
    exit 1
}

# Inject shebang to the script
sed -i '1i #!/usr/bin/env python3' "$INSTALL_DIR/VTScanX.py"

# Create wrapper script for global use
sudo tee "$BIN_PATH" > /dev/null <<EOF
#!/bin/bash
"$VENV_DIR/bin/python" "$INSTALL_DIR/VTScanX.py" "\$@"
EOF

sudo chmod +x "$BIN_PATH"

echo "[✔] VTScanX installed globally as 'vtscanx'"
echo "    Try running: vtscanx --help"
