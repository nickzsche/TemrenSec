#!/bin/sh
# Entrypoint of the temrensec-cli image.
#
# Two calling conventions:
#   1. GitHub Action (action/action.yml): positional inputs, first argument is the
#      target URL -> runs `temren scan` with the mapped flags.
#   2. Plain CLI usage: `docker run ghcr.io/nickzsche/temrensec-cli export -f sarif ...`
#      -> everything is forwarded verbatim to `temren`.
set -e

case "$1" in
  http://*|https://*) ;;              # action mode, handled below
  "") exec temren --help ;;
  *)  exec temren "$@" ;;             # passthrough mode
esac

TARGET="$1"
DEPTH="${2:-2}"
FORMAT="${3:-sarif}"
OUTPUT="${4:-temren-results.sarif}"
TIMEOUT="${5:-30}"
RATE="${6:-10}"
MAX_PAGES="${7:-50}"
AUTH_TOKEN="${8:-}"
AUTH_COOKIE="${9:-}"
EXTRA_ARGS="${10:-}"

# Positional args stay bound above; rebuild "$@" as the real temren argv so
# that values containing spaces are never re-split by eval.
set -- scan --target "$TARGET" --depth "$DEPTH" --format "$FORMAT" --output "$OUTPUT" \
       --timeout "$TIMEOUT" --rate "$RATE" --max-pages "$MAX_PAGES" --silent

if [ -n "$AUTH_TOKEN" ]; then
  set -- "$@" --auth-token "$AUTH_TOKEN"
fi

if [ -n "$AUTH_COOKIE" ]; then
  # `--auth-cookie` is repeatable; accept "a=1; b=2" and split on ';'.
  OLDIFS=$IFS; IFS=';'
  for c in $AUTH_COOKIE; do
    c=$(printf '%s' "$c" | sed 's/^ *//; s/ *$//')
    [ -n "$c" ] && set -- "$@" --auth-cookie "$c"
  done
  IFS=$OLDIFS
fi

# --api-url/--api-key/--target-id default to these env vars inside temren.
if [ -n "$TEMREN_API_URL" ] && [ -n "$TEMREN_API_KEY" ] && [ -n "$TEMREN_TARGET_ID" ]; then
  set -- "$@" --upload
fi

if [ -n "$EXTRA_ARGS" ]; then
  # Intentional word splitting of user-supplied flags.
  # shellcheck disable=SC2086
  set -- "$@" $EXTRA_ARGS
fi

echo "::group::temren $*"
temren "$@"
STATUS=$?
echo "::endgroup::"

if [ "$STATUS" -ne 0 ]; then
  echo "::error::temren scan exited with status $STATUS"
  exit "$STATUS"
fi

echo "::notice::TemrenSec scan complete. Results saved to $OUTPUT"
