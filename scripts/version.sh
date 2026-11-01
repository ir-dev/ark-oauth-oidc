#!/usr/bin/env bash
#
# One version number for every package this repository publishes.
#
#   scripts/version.sh                 show what each manifest says
#   scripts/version.sh check [X.Y.Z]   fail unless every manifest agrees (and says X.Y.Z, if
#                                      given); on success prints the version on stdout
#   scripts/version.sh set X.Y.Z       write X.Y.Z into every manifest, then refresh uv.lock
#
# The release workflow (.github/workflows/release.yml) runs `check` and refuses to publish on a
# mismatch. Bump with `set`, never by hand: the Python __version__ has been left behind
# pyproject.toml more than once, and the access-denied page footer then names the wrong release.
#
# Plain X.Y.Z only. AssemblyVersion cannot carry a pre-release label, and NuGet, PyPI (PEP 440)
# and npm spell pre-releases three different ways.

set -euo pipefail
cd "$(dirname "$0")/.."

OIDC=Ark.oAuth.Oidc/Ark.oAuth.Oidc/Ark.oAuth.Oidc.csproj
CLIENT=Ark.oAuth.Oidc/Ark.oAuth.Client/Ark.oAuth.Client.csproj
PYPROJECT=ark_oauth_client_py/pyproject.toml
PYINIT=ark_oauth_client_py/src/ark_oauth_client/__init__.py
NPM=ark_oauth_client_nodejs/package.json

# label|file|regex whose first group is the version|suffix the version carries in that field
entries() {
	cat <<EOF
Version|$OIDC|<Version>([^<]*)</Version>|
AssemblyVersion|$OIDC|<AssemblyVersion>([^<]*)</AssemblyVersion>|.0
FileVersion|$OIDC|<FileVersion>([^<]*)</FileVersion>|.0
Version|$CLIENT|<Version>([^<]*)</Version>|
AssemblyVersion|$CLIENT|<AssemblyVersion>([^<]*)</AssemblyVersion>|.0
FileVersion|$CLIENT|<FileVersion>([^<]*)</FileVersion>|.0
version|$PYPROJECT|^version = "([^"]*)"|
__version__|$PYINIT|^__version__ = "([^"]*)"|
version|$NPM|^  "version": "([^"]*)"|
EOF
}

read_one() { RE="$2" perl -0777 -ne 'print $1 if /$ENV{RE}/m' "$1"; }

valid() {
	printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
		{ echo "error: '$1' is not a plain X.Y.Z version" >&2; exit 2; }
}

# Prints the table to stderr; returns 1 on any mismatch.
report() {
	local want=$1 bad=0 label file re suffix got mark
	while IFS='|' read -r label file re suffix; do
		got=$(read_one "$file" "$re")
		if [ -z "$want" ]; then
			mark=""
		elif [ "$got" = "$want$suffix" ]; then
			mark="ok"
		else
			mark="MISMATCH, want $want$suffix"; bad=1
		fi
		printf '  %-10s %-16s %-58s %s\n' "${got:-<none>}" "$label" "$file" "$mark" >&2
	done < <(entries)
	return $bad
}

case "${1:-show}" in
show)
	report ""
	;;
check)
	want=${2:-}
	[ -z "$want" ] || valid "$want"
	# With no expected version, the provider's csproj is the reference: it is the release.
	want=${want:-$(read_one "$OIDC" '<Version>([^<]*)</Version>')}
	if report "$want"; then
		echo "$want"
	else
		echo "error: versions disagree. Fix with: scripts/version.sh set <X.Y.Z>" >&2
		exit 1
	fi
	;;
set)
	[ -n "${2:-}" ] || { echo "usage: scripts/version.sh set X.Y.Z" >&2; exit 2; }
	valid "$2"
	while IFS='|' read -r label file re suffix; do
		RE="$re" NEW="$2$suffix" perl -0777 -pi -e \
			'/$ENV{RE}/m or die "no match in $ARGV\n"; substr($_, $-[1], $+[1] - $-[1]) = $ENV{NEW}' "$file"
	done < <(entries)
	if command -v uv >/dev/null 2>&1; then
		(cd ark_oauth_client_py && uv lock -q) ||
			echo "warning: uv lock failed; run it in ark_oauth_client_py" >&2
	fi
	report "$2"
	echo "Now write the release notes by hand: ark_oauth_client_py/CHANGELOG.md and" \
		"<PackageReleaseNotes> in both csproj files." >&2
	;;
*)
	echo "usage: scripts/version.sh [show | check [X.Y.Z] | set X.Y.Z]" >&2
	exit 2
	;;
esac
