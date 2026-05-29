#!/usr/bin/env bash
# Safety Kernel paper figures - local viewer
# Starts a local HTTP server, opens the browser, and tails until Ctrl-C.

set -e

PORT="${PORT:-8000}"
URL="http://localhost:${PORT}/index.html"

cd "$(dirname "$0")"

echo ""
echo "  Safety Kernel - Paper Figures"
echo "  =============================="
echo ""
echo "  Serving from: $(pwd)"
echo "  URL:          ${URL}"
echo ""
echo "  Ctrl-C to stop."
echo ""

# Open the browser after a short delay so the server is up.
( sleep 0.6 && {
  if command -v open >/dev/null 2>&1; then
    open "${URL}"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${URL}"
  elif command -v start >/dev/null 2>&1; then
    start "${URL}"
  fi
} ) &

# Prefer python3 if available, fall back to python2.
if command -v python3 >/dev/null 2>&1; then
  exec python3 -m http.server "${PORT}"
elif command -v python >/dev/null 2>&1; then
  exec python -m SimpleHTTPServer "${PORT}"
else
  echo "  No python found. Install Python 3, or run:"
  echo "    npx serve -p ${PORT} ."
  exit 1
fi
