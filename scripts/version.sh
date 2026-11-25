#!/usr/bin/env bash
#
# One version number for every package this repository publishes.
#
#   scripts/version.sh                 show what each manifest says
#   scripts/version.sh check [X.Y.Z]   fail unless every manifest agrees (and says X.Y.Z, if
#                                      given); on success prints the version on stdout
#   scripts/version.sh set X.Y.Z       write X.Y.Z into every manifest, then refresh uv.lock
#   scripts/version.sh next [patch|minor|major]
#                                      print the version the next release gets: the last release
#                                      with that part raised (patch when not said), or what the
#                                      manifests say when they are already ahead of that
#   scripts/version.sh stamp X.Y.Z     `set`, and the notes headed "Next release" are headed X.Y.Z
#
# The release workflow (.github/workflows/release.yml) asks `next` for the version unless one is
# typed into the run, then runs `stamp` on every runner. It commits nothing, so after a release
# the manifests and the "Next release" headings in git still describe the one before: run
# `stamp` with the released version and commit, before notes for the release after it are added.
# Change a version with `set` or `stamp`, never by hand: the Python __version__ has been left
# behind pyproject.toml more than once, and the access-denied page footer then names the wrong
# release.
#
# Plain X.Y.Z only. AssemblyVersion cannot carry a pre-release label, and NuGet, PyPI (PEP 440)
# and npm spell pre-releases three different ways.

set -euo pipefail
cd "$(dirname "$0")/.."

OIDC=Ark.oAuth.Oidc/Ark.oAuth.Oidc/Ark.oAuth.Oidc.csproj
CLIENT=Ark.oAuth.Oidc/Ark.oAuth.Client/Ark.oAuth.Client.csproj
# Not a package: its assembly ships inside Ark.oAuth.Oidc's, and says which release it came with.
AGENT=agents/agent-001-tenant-onboarding/Ark.Agents.TenantOnboarding/Ark.Agents.TenantOnboarding.csproj
PYPROJECT=ark_oauth_client_py/pyproject.toml
PYINIT=ark_oauth_client_py/src/ark_oauth_client/__init__.py
NPM=ark_oauth_client_nodejs/package.json
# The browser client is a separate npm package. A browser cannot read package.json at run time,
# so its VERSION is a literal in src/version.js; and unlike the Node client it has a lock file
# (dev dependencies), which carries the version twice.
NPMJS=ark_oauth_client_js/package.json
NPMJSLOCK=ark_oauth_client_js/package-lock.json
NPMJSVER=ark_oauth_client_js/src/version.js

# Where release notes are written ahead of a release, under "Next release" in place of a number
# nobody has chosen yet: a changelog heading, the first line of a <PackageReleaseNotes> entry, a
# bullet in the two guides that ship inside the provider package.
NOTES="$OIDC $CLIENT
ark_oauth_client_py/CHANGELOG.md ark_oauth_client_nodejs/CHANGELOG.md ark_oauth_client_js/CHANGELOG.md
Ark.oAuth.Oidc/Ark.oAuth.Oidc/MIGRATION.md Ark.oAuth.Oidc/Ark.oAuth.Oidc/AI-PROMPT.md"

# label|file|regex whose first group is the version|suffix the version carries in that field
entries() {
	cat <<EOF
Version|$OIDC|<Version>([^<]*)</Version>|
AssemblyVersion|$OIDC|<AssemblyVersion>([^<]*)</AssemblyVersion>|.0
FileVersion|$OIDC|<FileVersion>([^<]*)</FileVersion>|.0
Version|$CLIENT|<Version>([^<]*)</Version>|
AssemblyVersion|$CLIENT|<AssemblyVersion>([^<]*)</AssemblyVersion>|.0
FileVersion|$CLIENT|<FileVersion>([^<]*)</FileVersion>|.0
Version|$AGENT|<Version>([^<]*)</Version>|
version|$PYPROJECT|^version = "([^"]*)"|
__version__|$PYINIT|^__version__ = "([^"]*)"|
version|$NPM|^  "version": "([^"]*)"|
version|$NPMJS|^  "version": "([^"]*)"|
VERSION|$NPMJSVER|^export const VERSION = '([^']*)'|
version|$NPMJSLOCK|^  "version": "([^"]*)"|
packages[""]|$NPMJSLOCK|^    "": \{\s*"name": "[^"]*",\s*"version": "([^"]*)"|
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

write_version() {
	local label file re suffix
	while IFS='|' read -r label file re suffix; do
		RE="$re" NEW="$1$suffix" perl -0777 -pi -e \
			'/$ENV{RE}/m or die "no match in $ARGV\n"; substr($_, $-[1], $+[1] - $-[1]) = $ENV{NEW}' "$file"
	done < <(entries)
	if command -v uv >/dev/null 2>&1; then
		(cd ark_oauth_client_py && uv lock -q) ||
			echo "warning: uv lock failed; run it in ark_oauth_client_py" >&2
	fi
}

# "Next release" at the start of a line (after "## " or "- **", if any) becomes the version.
# Quoted or mid-sentence it is prose and is left alone.
head_notes() {
	local file n
	for file in $NOTES; do
		n=$(NEW="$1" perl -0777 -pi -e \
			'$n = s/^((?:## |- \*\*)?)Next release\b/$1$ENV{NEW}/mg; print STDERR $n + 0' "$file" 2>&1)
		[ "$n" = 0 ] || printf '  %-10s %-16s %s\n' "$1" "was Next release" "$file" >&2
	done
}

# The highest vX.Y.Z tag: the release workflow creates the tag last, so it names the last release
# that went out whole. Asked of origin, because a runner's checkout carries no tags and a
# laptop's may be behind; local tags only when origin cannot be reached.
released() {
	local tags
	if ! tags=$(git ls-remote --tags --refs origin 'v*' 2>/dev/null); then
		echo "warning: origin cannot be reached, so this is from local tags" >&2
		tags=$(git tag -l 'v*')
	fi
	printf '%s\n' "$tags" | sed -nE 's#^(.*refs/tags/)?v([0-9]+\.[0-9]+\.[0-9]+)$#\2#p' |
		sort -t. -k1,1n -k2,2n -k3,3n | tail -1
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
	write_version "$2"
	report "$2"
	echo "Now write the release notes by hand: CHANGELOG.md in ark_oauth_client_py," \
		"ark_oauth_client_nodejs and ark_oauth_client_js, and <PackageReleaseNotes> in both" \
		"csproj files. Or \`stamp\`, when they are already written under \"Next release\"." >&2
	;;
next)
	part=${2:-patch}
	manifest=$(read_one "$OIDC" '<Version>([^<]*)</Version>')
	valid "$manifest"
	last=$(released)
	if [ -z "$last" ]; then
		want=$manifest
		why="nothing is released yet, so what the manifests say"
	else
		IFS=. read -r major minor patch <<<"$last"
		case "$part" in
		patch) patch=$((10#$patch + 1)) ;;
		minor) minor=$((10#$minor + 1)) patch=0 ;;
		major) major=$((10#$major + 1)) minor=0 patch=0 ;;
		*) echo "usage: scripts/version.sh next [patch|minor|major]" >&2; exit 2 ;;
		esac
		want="$major.$minor.$patch"
		why="$part after v$last, the last release; the manifests say $manifest"
		# Manifests ahead of that are a number somebody chose with `set` and committed.
		highest=$(printf '%s\n%s\n' "$want" "$manifest" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)
		if [ "$highest" != "$want" ]; then
			want=$manifest
			why="what the manifests say, which is past v$last, the last release"
		fi
	fi
	echo "next: $want ($why)" >&2
	echo "$want"
	;;
stamp)
	[ -n "${2:-}" ] || { echo "usage: scripts/version.sh stamp X.Y.Z" >&2; exit 2; }
	valid "$2"
	write_version "$2"
	head_notes "$2"
	report "$2"
	;;
*)
	echo "usage: scripts/version.sh [show | check [X.Y.Z] | set X.Y.Z | next [patch|minor|major] | stamp X.Y.Z]" >&2
	exit 2
	;;
esac
