#!/bin/bash
# Wordlist Downloader for Hashcat MCP Server
# Downloads common wordlists into the wordlists/ directory
#
# Usage:
#   ./download-wordlists.sh              # download all
#   ./download-wordlists.sh rockyou      # download specific list

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORDLIST_DIR="$SCRIPT_DIR/wordlists"
mkdir -p "$WORDLIST_DIR"

download() {
    local name="$1"
    local url="$2"
    local file="$WORDLIST_DIR/$name"

    if [ -f "$file" ]; then
        echo "[✓] $name already exists ($(du -h "$file" | cut -f1))"
        return 0
    fi

    echo "[+] Downloading $name..."
    echo "    URL: $url"

    if echo "$url" | grep -q '\.gz$'; then
        curl -sL "$url" | gunzip > "$file" 2>/dev/null || {
            echo "[-] Download failed, trying alternative..."
            curl -sL -o "${file}.gz" "$url" && gunzip "${file}.gz" && rm -f "${file}.gz"
        }
    else
        curl -sL -o "$file" "$url"
    fi

    if [ -f "$file" ] && [ -s "$file" ]; then
        local size=$(du -h "$file" | cut -f1)
        local lines=$(wc -l < "$file" | tr -d ' ')
        echo "[✓] $name saved ($size, $lines words)"
    else
        echo "[-] Failed to download $name"
        rm -f "$file" 2>/dev/null
        return 1
    fi
}

# --- Wordlists ---

if [ $# -eq 0 ] || [ "$1" = "rockyou" ]; then
    download "rockyou.txt" "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
fi

if [ $# -eq 0 ] || [ "$1" = "common" ]; then
    download "common.txt" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
fi

if [ $# -eq 0 ] || [ "$1" = "best1050" ]; then
    download "best1050.txt" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
fi

if [ $# -eq 0 ] || [ "$1" = "darkweb" ]; then
    download "darkweb2017-top10000.txt" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt"
fi

echo ""
echo "=== Wordlists in $WORDLIST_DIR ==="
ls -lh "$WORDLIST_DIR" 2>/dev/null || echo "(empty)"
