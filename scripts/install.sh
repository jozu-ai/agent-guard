#!/usr/bin/env bash
#
# AgentGuard installer for macOS on Apple Silicon.
#
#   curl -fsSL https://github.com/jozu-ai/agent-guard/releases/latest/download/install.sh | bash
#
# Everything this script fetches is public: no GitHub account, no `gh` CLI,
# no token, and no membership of the jozu-ai org. That matters because the
# people who run it first are usually evaluating AgentGuard before buying,
# on a laptop where installing and authenticating extra tooling needs a
# ticket.
#
# Environment overrides:
#   VERSION      Release tag to install (e.g. v0.7.1). Defaults to latest.
#   INSTALL_DIR  Where to put the binary. Defaults to /usr/local/bin.
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

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

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
require_space() {
  local dir="$1" label="$2" avail
  # Walk up to the nearest existing ancestor: /usr/local/bin may not exist
  # yet on a clean machine.
  while [ ! -d "$dir" ] && [ "$dir" != "/" ]; do
    dir="$(dirname "$dir")"
  done
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
    https://*) ;;
    http://127.0.0.1*|http://localhost*|http://\[::1\]*) ;;
    *) error "AGENTGUARD_BASE_URL must use https (got $1)" ;;
  esac
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

  want="$(awk -v name="$asset_name" '$2 == name {print $1; exit}' "$sums_file")"
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
  if mkdir -p "$INSTALL_DIR" 2>/dev/null && [ -w "$INSTALL_DIR" ]; then
    mv -f "$src" "$dest"
  else
    info "Installing to $INSTALL_DIR (requires sudo)..."
    sudo mkdir -p "$INSTALL_DIR"
    sudo mv -f "$src" "$dest"
    sudo chmod 755 "$dest"
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

  # Global, not local: the EXIT trap fires after main returns, and a local
  # would be out of scope by then -- which under `set -u` turns a successful
  # install's final act into an "unbound variable" error and leaks the
  # download.
  workdir="$(mktemp -d)"
  trap cleanup EXIT

  require_space "$workdir" "The temporary directory ($workdir)"
  require_space "$INSTALL_DIR" "$INSTALL_DIR"

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

  info "Installed: $("$installed_path" --version)"
  info "Location:  $installed_path"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) warn "$INSTALL_DIR is not on your PATH. Add it, or run $installed_path directly." ;;
  esac

  cat <<EOF

Next steps:
  agentguard policy add jozu.ml/jozu/agentguard-policies:vm-standard
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
