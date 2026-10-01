#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/src"
for h in g++ make; do
  command -v "$h" >/dev/null 2>&1 || { echo "falta $h: sudo apt-get install -y build-essential libssl-dev" >&2; exit 1; }
done
[ -f /usr/include/openssl/des.h ] || echo "[!] no se ve openssl/des.h: sudo apt-get install -y libssl-dev"
make -f makefile.linux
mkdir -p ../bin
cp -f rtgen rtsort rtdump rcrack charset.txt ../bin/
rm -f rtgen rtsort rtdump rcrack
echo "[+] listo: $(cd ../bin && pwd)"
