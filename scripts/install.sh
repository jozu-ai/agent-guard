#!/usr/bin/env bash
#
# AgentGuard installer for macOS on Apple Silicon.
#
#   curl -fsSL https://raw.githubusercontent.com/jozu-ai/agent-guard/main/scripts/install.sh | bash
#
# Everything this script fetches is public: no GitHub account, no `gh` CLI,
# no token, and no membership of the jozu-ai org. That matters because the
# people who run it first are usually evaluating AgentGuard before buying,
# on a laptop where installing and authenticating extra tooling needs a
# ticket.
#
# Environment overrides:
#   VERSION      Release tag to install (e.g. v0.7.1). Defaults to latest.
#   INSTALL_DIR  Where to put the binary. Defaults to ~/.local/bin when that
#                is already on your PATH, otherwise /usr/local/bin.
#   AGENTGUARD_BASE_URL
#                Directory URL holding `agentguard` and `checksums.txt`, for
#                organizations that re-host release artifacts internally
#                instead of allowing direct egress to github.com. The
#                signature and checksum gates below still apply.

set -euo pipefail

# Public release mirror. The development repo (jozu-ai/agentguard) is
# private, so anything pointing an installer at it fails with a bare 404 for
# every prospect and most employees.
REPO="jozu-ai/agent-guard"

# default_install_dir picks somewhere the binary will actually be found,
# preferring a location that needs no password.
#
# /usr/local/bin is the only directory on macOS's stock PATH (see
# /etc/paths) that software installs into, which is why it is the fallback
# even though Apple Silicon leaves it root-owned and therefore needs sudo.
# ~/.local/bin is NOT on the stock PATH, so installing there blind would
# produce an install the user cannot run; it is only chosen when the caller
# already has it on PATH, which is exactly the case where sudo is pure
# friction.
default_install_dir() {
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    printf '/usr/local/bin'
    return
  fi
  case ":$PATH:" in
    *":$HOME/.local/bin:"*)
      printf '%s/.local/bin' "$HOME"
      return
      ;;
  esac
  printf '/usr/local/bin'
}

INSTALL_DIR="${INSTALL_DIR:-$(default_install_dir)}"

ASSET="agentguard"
CHECKSUMS_ASSET="checksums.txt"

# Apple Developer ID Team Identifier that every real AgentGuard release is
# signed with. Must stay in sync with pkg/selfupdate.ExpectedTeamID, which
# gates `agentguard update` the same way -- the two are the only paths by
# which a released binary lands on a user's machine.
EXPECTED_TEAM_ID="PMHBCVV9C2"

# Absolute path, never a PATH lookup: codesign IS the trust gate here, so
# resolving it through PATH would make the gate only as trustworthy as PATH
# (a poisoned profile could drop in an `exit 0` shim). /usr/bin/codesign is
# SIP-protected. Same reasoning as pkg/selfupdate's codesignPath.
#
# codesign ships with macOS itself, so requiring it costs the user nothing:
# it is a real binary in /usr/bin linked against CodesignKit and
# AppleMobileFileIntegrity, not one of the Xcode Command Line Tools shims
# (those are hardlinks to a stub that links libxcselect and prompt to
# install the CLT on first use).
CODESIGN="/usr/bin/codesign"

# Download needs room for the binary; the install directory needs room for
# the copy that lands there. ~600MB each, with headroom.
REQUIRED_KB=700000

workdir=""
cleanup() { [ -n "${workdir:-}" ] && rm -rf "$workdir"; return 0; }

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33mWarning:\033[0m %s\n' "$*" >&2; }
error() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

# require_platform refuses anything but macOS on Apple Silicon, which is all
# the released binary supports (it needs Virtualization.framework).
require_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  [ "$os" = "Darwin" ] || error "AgentGuard requires macOS (got $os)"
  [ "$arch" = "arm64" ] || error "AgentGuard requires Apple Silicon (got $arch)"
  [ -x "$CODESIGN" ] || error "$CODESIGN not found -- cannot verify the download's signature"
}

# require_space fails early rather than after a multi-hundred-MB download
# that dies partway through with a confusing write error.
# nearest_existing walks up to the closest directory that exists, so a target
# that has not been created yet can still be probed.
nearest_existing() {
  local dir="$1"
  while [ ! -d "$dir" ] && [ "$dir" != "/" ]; do
    dir="$(dirname "$dir")"
  done
  printf '%s' "$dir"
}

require_space() {
  local dir="$1" label="$2" avail
  dir="$(nearest_existing "$dir")"
  avail="$(df -Pk "$dir" | awk 'NR==2 {print $4}')"
  if [ -n "$avail" ] && [ "$avail" -lt "$REQUIRED_KB" ]; then
    error "$label has $((avail / 1024))MB free; AgentGuard needs about $((REQUIRED_KB / 1024))MB there"
  fi
}

# require_https refuses a plaintext base URL. The signature gate below is
# what actually stops a hostile mirror from installing foreign code, but
# plaintext still lets a network attacker choose *which* genuinely signed
# release you get, which is a downgrade to a known-vulnerable version.
# Loopback is exempt so an internal mirror can be smoke-tested before its
# TLS is in place.
require_https() {
  case "$1" in
    https://*) return 0 ;;
    http://*) ;;
    *) error "AGENTGUARD_BASE_URL must use https (got $1)" ;;
  esac

  # Loopback over plaintext is fine; anything else is not. Match the host
  # exactly, terminated by :port, /path or end of string. A prefix glob is
  # not good enough here and was wrong when first written: http://127.0.0.1*
  # also matches http://127.0.0.1.evil.com, and http://localhost* matches
  # http://localhost.attacker.io, which hands a remote attacker the very
  # downgrade this function exists to prevent.
  local rest="${1#http://}"
  case "$rest" in
    127.0.0.1|127.0.0.1:*|127.0.0.1/*) return 0 ;;
    localhost|localhost:*|localhost/*) return 0 ;;
    "[::1]"|"[::1]:"*|"[::1]/"*) return 0 ;;
  esac
  error "AGENTGUARD_BASE_URL must use https (got $1)"
}

# source_label names where the binary is about to come from, so an install
# that silently reads a stale AGENTGUARD_BASE_URL from the environment is
# visible rather than mysterious.
source_label() {
  if [ -n "${AGENTGUARD_BASE_URL:-}" ]; then
    printf '%s' "${AGENTGUARD_BASE_URL%/}"
  else
    printf 'https://github.com/%s (%s)' "$REPO" "${TAG:-latest release}"
  fi
}

# require_install_access fails before the download rather than after it.
# Escalation is decided at the end of a 550MB transfer, and a machine with
# no controlling terminal -- an MDM run, a provisioning script, a CI step,
# anything driving this non-interactively -- cannot answer sudo's password
# prompt. Discovering that after the transfer wastes the transfer and
# reports it as a raw sudo error, so check up front.
require_install_access() {
  # Probe, never create: this runs before the download, and a refused
  # install (404, checksum mismatch, wrong signing team) must not leave a
  # directory tree behind that the user never asked for. install_binary
  # creates the directory once there is actually something to put in it.
  if [ -w "$(nearest_existing "$INSTALL_DIR")" ]; then
    return 0
  fi

  command -v sudo >/dev/null 2>&1 || error "$INSTALL_DIR is not writable and sudo is not available.
  Set INSTALL_DIR to a directory you own, e.g. INSTALL_DIR=\$HOME/.local/bin"

  # Passwordless sudo, or a terminal on which sudo can prompt. sudo reads
  # the password from /dev/tty, not stdin, which is why this tests the
  # terminal rather than stdin -- under `curl | bash` stdin is the script
  # itself, and prompting still works fine.
  if sudo -n true 2>/dev/null; then
    return 0
  fi
  if [ -c /dev/tty ] && { : < /dev/tty; } 2>/dev/null; then
    return 0
  fi

  error "$INSTALL_DIR needs sudo to write to, but there is no terminal to ask for a password on.
  Either run this with sudo already granted:
      sudo INSTALL_DIR=$INSTALL_DIR bash install.sh
  or install somewhere you own:
      INSTALL_DIR=\$HOME/.local/bin"
}

# asset_url builds the public download URL for one release asset. The
# /releases/latest/download/ and /releases/download/<tag>/ forms are plain
# redirects -- deliberately not the REST API, which is rate-limited to 60
# requests/hour per IP for unauthenticated callers and would therefore fail
# intermittently for a whole office behind one NAT.
asset_url() {
  local name="$1"
  if [ -n "${AGENTGUARD_BASE_URL:-}" ]; then
    printf '%s/%s' "${AGENTGUARD_BASE_URL%/}" "$name"
  elif [ -n "${TAG:-}" ]; then
    printf 'https://github.com/%s/releases/download/%s/%s' "$REPO" "$TAG" "$name"
  else
    printf 'https://github.com/%s/releases/latest/download/%s' "$REPO" "$name"
  fi
}

# fetch downloads url to dest. required=no turns a miss into a soft failure
# (returns 1) instead of aborting, for assets older releases may not carry.
fetch() {
  local url="$1" dest="$2" required="${3:-yes}" curl_status=0

  if [ "$required" = "yes" ]; then
    curl -fL --progress-bar --retry 3 --retry-delay 2 -o "$dest" "$url" || curl_status=$?
  else
    curl -fsSL --retry 2 -o "$dest" "$url" 2>/dev/null || curl_status=$?
    return "$curl_status"
  fi

  [ "$curl_status" -eq 0 ] && return 0

  # Diagnose from the HTTP status rather than curl's exit code: a 404 on a
  # release asset surfaces as exit 22 or 56 depending on the HTTP version
  # negotiated, so the code alone cannot tell "no such release" from "the
  # network ate it".
  local http_status
  http_status="$(curl -sIL -o /dev/null -w '%{http_code}' --retry 1 "$url" 2>/dev/null || true)"

  case "$http_status" in
    404)
      error "No such release asset: $url
  Check the available versions at https://github.com/$REPO/releases"
      ;;
    000|"")
      case "$curl_status" in
        35|60)
          error "TLS handshake with github.com was rejected (curl $curl_status).
  A TLS-inspecting corporate proxy is the usual cause. Either allow
  github.com and release-assets.githubusercontent.com through it, or
  re-host the release assets internally and point AGENTGUARD_BASE_URL at
  them."
          ;;
        *)
          error "Could not reach $url (curl $curl_status).
  If this machine reaches the internet through a proxy, set https_proxy
  before re-running, or re-host the assets internally and point
  AGENTGUARD_BASE_URL at them."
          ;;
      esac
      ;;
    *)
      error "Download failed with HTTP $http_status fetching $url (curl $curl_status)"
      ;;
  esac
}

# verify_checksum compares path's SHA-256 against the entry for asset_name in
# a checksums.txt. Defense in depth alongside the signature gate, not a
# replacement for it: a missing checksums file is tolerated (releases before
# v0.7.1 predate it) while a mismatch is fatal.
verify_checksum() {
  local path="$1" sums_file="$2" asset_name="$3" want got

  if [ ! -s "$sums_file" ]; then
    warn "This release publishes no $CHECKSUMS_ASSET -- relying on the signature check alone."
    return 0
  fi

  # Match on the basename, after stripping the "*" that `sha256sum -b`
  # prefixes and any directory component from generating in a dist/ tree.
  # Exact equality on the raw field would turn a release-tooling change into
  # a silently skipped checksum rather than a failure.
  want="$(awk -v name="$asset_name" '
    { f = $2; sub(/^\*/, "", f); sub(/^.*\//, "", f) }
    f == name { print $1; exit }' "$sums_file")"
  if [ -z "$want" ]; then
    warn "$CHECKSUMS_ASSET has no entry for $asset_name -- relying on the signature check alone."
    return 0
  fi

  got="$(shasum -a 256 "$path" | awk '{print $1}')"
  if [ "$(printf '%s' "$got" | tr 'A-Z' 'a-z')" != "$(printf '%s' "$want" | tr 'A-Z' 'a-z')" ]; then
    error "Checksum mismatch for $asset_name:
  got  $got
  want $want
  Refusing to install."
  fi
  info "Checksum verified"
}

# require_apple_signature is the hard trust gate. One `--verify --strict -R`
# establishes both properties that matter: the bytes on disk are the bytes
# that were signed, and the signing certificate chains to Apple with a leaf
# OU of EXPECTED_TEAM_ID.
#
# A bare `codesign -v` (what this script used to do) establishes neither in
# any useful sense -- for self-signed code the designated requirement is
# embedded in the same signature being checked, so it passes trivially.
require_apple_signature() {
  local path="$1" team

  if "$CODESIGN" --verify --strict \
      -R "=anchor apple generic and certificate leaf[subject.OU] = $EXPECTED_TEAM_ID" \
      "$path" 2>/dev/null; then
    info "Signature verified (Developer ID team $EXPECTED_TEAM_ID)"
    return 0
  fi

  # Say which of the two properties broke; "signed by team X, expected Y" is
  # a far more actionable message than codesign's own wording.
  if ! "$CODESIGN" --verify --strict "$path" 2>/dev/null; then
    error "The downloaded file is not validly signed -- it may be corrupt or truncated. Refusing to install."
  fi
  team="$("$CODESIGN" -dv --verbose=4 "$path" 2>&1 | awk -F= '/^TeamIdentifier=/ {print $2; exit}')"
  if [ -n "$team" ] && [ "$team" != "not set" ]; then
    error "The downloaded file is signed by team $team, expected $EXPECTED_TEAM_ID. Refusing to install."
  fi
  error "The downloaded file is not signed by an Apple-anchored Jozu certificate. Refusing to install."
}

# check_notarization is advisory only. The ticket lives with Apple, so this
# needs egress to Apple's notary endpoints that a locked-down network may
# not allow, and a freshly published release can take a few minutes to
# propagate. Neither is a reason to block an install whose signature already
# verified against the pinned team.
check_notarization() {
  local path="$1"
  if ! "$CODESIGN" -vv --test-requirement="=notarized" "$path" >/dev/null 2>&1; then
    warn "Could not confirm notarization with Apple (offline, blocked, or a just-published release). The Developer ID signature verified, so installation continues."
  fi
}

# install_binary moves the verified binary into place, escalating only if the
# destination genuinely is not writable. The result goes into the global
# installed_path rather than stdout: the sudo branch prints a status line,
# and a caller capturing stdout would otherwise splice that line into the
# path it thinks it got back.
installed_path=""
install_binary() {
  local src="$1" dest="$INSTALL_DIR/$ASSET"

  # `mkdir -p` first, then test writability: requiring the directory to
  # already exist sent every install to a missing-but-creatable path (a
  # fresh ~/.local/bin, say) down the sudo branch, which prompts for a
  # password nobody needed and leaves a root-owned directory in the user's
  # home. Escalate only when creating or writing it genuinely fails.
  # Stage inside INSTALL_DIR and rename over the target, rather than moving
  # from the temp directory onto it. A move across volumes is a copy plus a
  # truncate, so an interrupted install would leave a partial, executable
  # binary on PATH that verification never saw; a rename within one
  # directory is atomic, and it also leaves a running agentguard's inode
  # alone instead of truncating it underneath the process.
  #
  # chmod 755 explicitly in both branches: `chmod +x` is filtered by umask,
  # so under umask 077 the non-sudo branch would install 0700 and nothing
  # else on the machine could run it.
  local staged="$dest.new.$$"
  if mkdir -p "$INSTALL_DIR" 2>/dev/null && [ -w "$INSTALL_DIR" ]; then
    if ! cp -f "$src" "$staged"; then
      rm -f "$staged"
      error "could not write to $INSTALL_DIR"
    fi
    chmod 755 "$staged"
    mv -f "$staged" "$dest"
  else
    info "Installing to $INSTALL_DIR (requires sudo)..."
    sudo mkdir -p "$INSTALL_DIR"
    if ! sudo cp -f "$src" "$staged"; then
      sudo rm -f "$staged"
      error "could not write to $INSTALL_DIR even with sudo"
    fi
    sudo chmod 755 "$staged"
    # mv keeps the temp file's ownership, so an elevated install would
    # otherwise leave a user-owned binary sitting in a root-owned directory
    # that is on every account's PATH: anything running as that user could
    # then replace, without a password, a binary other users and root
    # execute. Tolerate failure rather than abort a working install -- some
    # filesystems have no meaningful ownership -- but say so.
    sudo chown root:wheel "$staged" 2>/dev/null ||
      warn "could not set root ownership on $dest; it stays writable by your user"
    sudo mv -f "$staged" "$dest"
  fi

  installed_path="$dest"
}

main() {
  require_platform
  command -v curl >/dev/null 2>&1 || error "curl is required"
  command -v shasum >/dev/null 2>&1 || error "shasum is required"

  # Resolve the tag: bare versions get a v prefix, "latest" (or unset) uses
  # the mirror's latest-release redirect.
  TAG=""
  if [ -n "${VERSION:-}" ] && [ "$VERSION" != "latest" ]; then
    case "$VERSION" in
      v*) TAG="$VERSION" ;;
      nightly)
        error "Nightly builds are internal and are not published to $REPO. Install a tagged release instead: https://github.com/$REPO/releases"
        ;;
      *) TAG="v${VERSION}" ;;
    esac
  fi

  # Arm the trap before creating the directory, not after: in between, a
  # signal would leave the download behind with nothing registered to
  # remove it. cleanup tolerates an empty workdir precisely so it can be
  # armed first.
  #
  # workdir is global, not local, because the EXIT trap fires after main
  # returns -- a local would be out of scope by then, which under `set -u`
  # turns a successful install's final act into an "unbound variable" error
  # and leaks the download.
  trap cleanup EXIT
  # Explicit template: BSD mktemp ignores $TMPDIR unless it is given one
  # (it uses _CS_DARWIN_USER_TEMP_DIR instead), which silently defeats any
  # caller trying to isolate where the download lands.
  workdir="$(mktemp -d "${TMPDIR:-/tmp}/agentguard.XXXXXXXX")"

  require_space "$workdir" "The temporary directory ($workdir)"
  require_space "$INSTALL_DIR" "$INSTALL_DIR"
  require_install_access

  if [ -n "${AGENTGUARD_BASE_URL:-}" ]; then
    require_https "$AGENTGUARD_BASE_URL"
    warn "Installing from a custom source. Verification pins Jozu's signing identity, not the version, so a stale mirror can serve an older signed release."
  fi

  info "Source: $(source_label)"
  info "Downloading agentguard ${TAG:-(latest)} -- about 550MB..."
  fetch "$(asset_url "$ASSET")" "$workdir/$ASSET"

  fetch "$(asset_url "$CHECKSUMS_ASSET")" "$workdir/$CHECKSUMS_ASSET" no || true
  verify_checksum "$workdir/$ASSET" "$workdir/$CHECKSUMS_ASSET" "$ASSET"

  chmod +x "$workdir/$ASSET"
  require_apple_signature "$workdir/$ASSET"
  check_notarization "$workdir/$ASSET"

  install_binary "$workdir/$ASSET"

  # Capture first: a command substitution's exit status is discarded when
  # it is used as an argument, and set -e does not apply to it either, so
  # inlining this would report a binary that cannot execute as a successful
  # install and exit 0 -- which any MDM or wrapper keying off the exit code
  # would believe.
  local version
  if ! version="$("$installed_path" --version 2>&1)"; then
    error "installed $installed_path but it does not run:
  $version"
  fi
  info "Installed: $version"
  info "Location:  $installed_path"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) warn "$INSTALL_DIR is not on your PATH. Add it, or run $installed_path directly." ;;
  esac

  cat <<EOF

Next steps:
  agentguard run claude-code --workspace ~/projects/your-app

The first run extracts a ~1.5GB Linux disk image to ~/.agentguard/vm/ and
takes a few extra seconds. Later runs reuse it.
EOF
}

# Only run when executed or piped into bash, so the functions above can be
# sourced by scripts/install_test.sh. Piped into bash, BASH_SOURCE is unset.
if [ -z "${BASH_SOURCE[0]:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
