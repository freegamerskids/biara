#!/bin/sh
# Install or update biara from the latest successful Release workflow build of a branch
# (Linux x86-64, macOS arm64):
#
#   curl -fsSL https://raw.githubusercontent.com/freegamerskids/biara/main/scripts/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --branch my-branch
#
# Builds are GitHub Actions artifacts, which GitHub serves only to signed-in users: this uses
# the `gh` CLI when it is logged in, else a token in GH_TOKEN or GITHUB_TOKEN (curl, unzip).
#
# Layout: the archive unpacks into $BIARA_HOME/biara-<version>-<platform>/ (default
# ~/.local/share/biara), `current` points at it, and the bin directory (default ~/.local/bin)
# gets `biara` and `biara-ui` links. An installed `biara update` runs this script again.
set -eu

repo=${BIARA_REPO:-freegamerskids/biara}
branch=main
archive=
home=
bin=
modify_path=1

usage() {
    cat <<EOF
usage: install.sh [--branch NAME] [--archive FILE] [--home DIR] [--bin DIR] [--no-modify-path]

  --branch NAME       install the latest successful build of NAME (default: main)
  --archive FILE      install this biara-*.tar.xz instead of downloading one
  --home DIR          installation directory (default: \$BIARA_HOME or ~/.local/share/biara)
  --bin DIR           where the biara and biara-ui links go (default: ~/.local/bin)
  --no-modify-path    do not add the bin directory to the shell's PATH
EOF
}
die() {
    echo "install.sh: $*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case $1 in
    --branch) [ $# -ge 2 ] || die "$1 needs a value"; branch=$2; shift 2 ;;
    --archive) [ $# -ge 2 ] || die "$1 needs a value"; archive=$2; shift 2 ;;
    --home) [ $# -ge 2 ] || die "$1 needs a value"; home=$2; shift 2 ;;
    --bin) [ $# -ge 2 ] || die "$1 needs a value"; bin=$2; shift 2 ;;
    --no-modify-path) modify_path=0; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; die "unknown option $1" ;;
    esac
done

home=${home:-${BIARA_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/biara}}
# An update keeps the bin directory chosen at installation.
if [ -z "$bin" ] && [ -f "$home/install.conf" ]; then
    bin=$(sed -n 's/^bin=//p' "$home/install.conf")
fi
bin=${bin:-$HOME/.local/bin}

case "$(uname -s)-$(uname -m)" in
Linux-x86_64) platform=x86_64-linux ;;
Darwin-arm64) platform=arm64-macos ;;
*) die "no biara build for $(uname -s) $(uname -m): only Linux x86-64 and macOS arm64" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# The archive of the latest successful Release run on $branch, into $tmp.
download() {
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        run=$(gh run list -R "$repo" --workflow release.yml --branch "$branch" --status success \
            --limit 1 --json databaseId --jq '.[0].databaseId // empty')
        [ -n "$run" ] || die "no successful build of branch $branch"
        echo "Downloading dist-$platform from run $run ($branch)"
        gh run download "$run" -R "$repo" -n "dist-$platform" -D "$tmp/download"
        return
    fi
    token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
    [ -n "$token" ] || die "build artifacts need GitHub sign-in: run 'gh auth login', or set GH_TOKEN"
    command -v unzip >/dev/null 2>&1 || die "unzip is required without the gh CLI"
    api() {
        curl -fsSL -H "Authorization: Bearer $token" -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/$repo/$1"
    }
    encoded=$(printf '%s' "$branch" | sed 's|%|%25|g; s|/|%2F|g; s|#|%23|g; s|&|%26|g; s|+|%2B|g')
    # The first "id" of the response is the newest matching run's.
    run=$(api "actions/workflows/release.yml/runs?branch=$encoded&status=success&per_page=1" |
        grep -o '"id": *[0-9]*' | head -n 1 | grep -o '[0-9]*$' || true)
    [ -n "$run" ] || die "no successful build of branch $branch"
    url=$(api "actions/runs/$run/artifacts?name=dist-$platform" |
        grep -o '"archive_download_url": *"[^"]*"' | head -n 1 | sed 's/.*"\(http[^"]*\)"$/\1/' || true)
    [ -n "$url" ] || die "run $run has no dist-$platform artifact (expired, or that build failed)"
    echo "Downloading dist-$platform from run $run ($branch)"
    curl -fsSL -H "Authorization: Bearer $token" -o "$tmp/artifact.zip" "$url"
    mkdir -p "$tmp/download"
    unzip -q "$tmp/artifact.zip" -d "$tmp/download"
}

if [ -z "$archive" ]; then
    download
    for f in "$tmp"/download/biara-*-"$platform".tar.xz; do archive=$f; done
    [ -f "$archive" ] || die "the artifact holds no biara-*-$platform.tar.xz"
fi
[ -f "$archive" ] || die "$archive: no such file"

mkdir -p "$tmp/unpack"
tar -xJf "$archive" -C "$tmp/unpack"
name=
for d in "$tmp"/unpack/biara-*; do [ -x "$d/biara" ] && name=$(basename "$d"); done
[ -n "$name" ] || die "$archive is not a biara archive"

mkdir -p "$home" "$bin"
rm -rf "${home:?}/$name"
mv "$tmp/unpack/$name" "$home/$name"
# Browsers quarantine downloads; Gatekeeper then refuses the unsigned binaries.
if [ "$(uname -s)" = Darwin ]; then
    xattr -dr com.apple.quarantine "$home/$name" 2>/dev/null || true
fi
ln -sfn "$name" "$home/current"
for tool in biara biara-ui; do
    ln -sfn "$home/current/$tool" "$bin/$tool"
done
printf 'bin=%s\n' "$bin" >"$home/install.conf"
# Earlier versions; running ones keep their open files.
for d in "$home"/biara-*-"$platform"; do
    [ "$(basename "$d")" = "$name" ] || rm -rf "$d"
done
echo "Installed $name into $home; biara and biara-ui are in $bin"

case ":$PATH:" in
*":$bin:"*) exit 0 ;;
esac
if [ "$modify_path" = 0 ]; then
    echo "Add $bin to your PATH to run biara."
    exit 0
fi
line="export PATH=\"$bin:\$PATH\" # biara"
case $(basename "${SHELL:-sh}") in
zsh) rcs=${ZDOTDIR:-$HOME}/.zshrc ;;
bash)
    rcs=$HOME/.bashrc
    # macOS login shells read .bash_profile, not .bashrc.
    [ "$(uname -s)" = Darwin ] && rcs="$rcs $HOME/.bash_profile"
    ;;
fish)
    rcs=
    mkdir -p "$HOME/.config/fish/conf.d"
    printf 'fish_add_path -g %s\n' "$bin" >"$HOME/.config/fish/conf.d/biara.fish"
    echo "Added $bin to PATH in ~/.config/fish/conf.d/biara.fish"
    ;;
*) rcs=$HOME/.profile ;;
esac
for rc in $rcs; do
    if ! grep -qsF "$line" "$rc"; then
        printf '\n%s\n' "$line" >>"$rc"
        echo "Added $bin to PATH in $rc"
    fi
done
echo "Open a new shell (or run: export PATH=\"$bin:\$PATH\") to use biara."
