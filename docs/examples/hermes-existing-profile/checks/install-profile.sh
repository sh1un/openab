#!/bin/sh
set -eu

profile_root="/home/team-hermes-profile"
target_dir="$HOME/.hermes"
temporary="$target_dir/config.yaml.openab-profile.$$"

cleanup() {
  rm -f "$temporary"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$target_dir"
cp "$profile_root/config/config.yaml" "$temporary"
chmod 0600 "$temporary"
mv -f "$temporary" "$target_dir/config.yaml"
trap - EXIT HUP INT TERM

echo "Hermes profile files installed"
