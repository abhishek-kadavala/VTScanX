#!/bin/bash

echo "[*] Cloning VTScanX..."
git clone https://github.com/abhishek-kadavala/VTScanX.git /opt/VTScanX || exit 1

cd /opt/VTScanX || exit 1

echo "[*] Installing dependencies..."
pip3 install -r requirements.txt || exit 1

echo "[*] Ensuring shebang is present..."
if ! grep -q "#!/usr/bin/env python3" VTScanX.py; then
    sed -i '1i #!/usr/bin/env python3' VTScanX.py
fi

echo "[*] Making script executable..."
chmod +x VTScanX.py

echo "[*] Creating symlink to /usr/local/bin/vtscanx..."
ln -sf /opt/VTScanX/VTScanX.py /usr/local/bin/vtscanx

echo "[✓] VTScanX installed successfully. Run with: vtscanx --help"
