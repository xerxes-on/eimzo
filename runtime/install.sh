#!/usr/bin/env bash
set -euo pipefail

# Install a pinned provider from the official distribution. No certificate/password is needed here.
destination="${1:?Usage: bash install.sh /absolute/runtime/directory}"
[[ "$destination" = /* && "$destination" != / && "$destination" != *:* ]] || { echo 'Use an absolute runtime directory without colons.' >&2; exit 1; }
[[ ! -e "$destination" && ! -L "$destination" ]] || { echo 'Destination already exists; install a new version separately.' >&2; exit 1; }
for executable in curl sha256sum tar javac; do command -v "$executable" >/dev/null; done
parent="$(dirname -- "$destination")"
mkdir -p -- "$parent"
stage="$(mktemp -d "$parent/.eimzo-install.XXXXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 180 \
    'https://dls.soliq.uz/v6.4.7/E-IMZO-v6.4.7.tar.gz' -o "$stage/provider.tar.gz"
printf '%s  %s\n' 'c077152064cd44c8ade4ba877177061a2edfa039a2c0755751cc65e199611a76' "$stage/provider.tar.gz" | sha256sum --check --status
mkdir "$stage/unpacked" "$stage/ready"
tar -xzf "$stage/provider.tar.gz" -C "$stage/unpacked" --no-same-owner
cp -R "$stage/unpacked/E-IMZO/lib" "$stage/ready/lib"
javac -source 8 -target 8 -cp "$stage/ready/lib/*" -d "$stage/ready" "$(dirname -- "$0")/EimzoBridge.java"
printf '%s\n' 'Official E-IMZO 6.4.7 provider; archive SHA256 c077152064cd44c8ade4ba877177061a2edfa039a2c0755751cc65e199611a76' > "$stage/ready/VERSION"
chmod -R u=rwX,go=rX "$stage/ready"
mv -T --no-clobber -- "$stage/ready" "$destination"
[[ ! -e "$stage/ready" ]] || { echo 'Destination appeared during installation; nothing replaced.' >&2; exit 1; }
echo 'Native E-IMZO provider installed. No desktop service or browser is required.'
