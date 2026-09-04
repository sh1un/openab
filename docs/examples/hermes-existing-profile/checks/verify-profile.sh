#!/bin/sh
set -eu

test "$OPENAB_PROFILE_RUNTIME" = "hermes"
test -d "$OPENAB_PROFILE_ROOT"
test -d "$OPENAB_STATE_DIR"

actual_version="$(hermes --version 2>/dev/null || hermes-acp --version 2>/dev/null)"
case "$actual_version" in
  *"$OPENAB_PROFILE_RUNTIME_VERSION"*) ;;
  *)
    echo "Hermes runtime version does not match the profile contract" >&2
    exit 1
    ;;
esac

echo "Hermes profile compatibility check passed"
