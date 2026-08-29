#!/usr/bin/env bash
# ---------------------------------------------------------------------------------------------
# Ark Identity Server — start the whole sample end to end.
#
#   1. checks you have what you need (SDK, trusted dev certificate, free ports, admin password)
#   2. builds the solution
#   3. starts Ark.oAuth.Oidc.Host   — the identity provider  (https://localhost:7233)
#   4. waits for its discovery document, then verifies the sample registrations exist
#   5. starts Ark.Client.Web        — the sample client      (https://localhost:7255)
#   6. prints what is ready, what is not, and the exact fix for anything missing
#
# Ctrl-C stops both. Logs are written to .run-logs/.
#
# Usage:  ./run.sh [--no-build] [--no-browser] [--check-only] [--verbose]
#
# See GETTINGSTARTED.md for what every check means.
# ---------------------------------------------------------------------------------------------
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SLN_DIR="$ROOT/Ark.oAuth.Oidc"
SLN="$SLN_DIR/Ark.oAuth.Oidc.sln"
HOST_PROJ="$SLN_DIR/Ark.oAuth.Oidc.Host"
CLIENT_PROJ="$SLN_DIR/Ark.Client.Web"
LOG_DIR="$ROOT/.run-logs"
DB_FILE="$HOST_PROJ/data/ark_idp.db"

# --- Addresses -------------------------------------------------------------------------------
# Ports are read from each project's launchSettings.json, so changing a port there is enough —
# there is no second copy here to keep in step. Client ids are the stable identifiers used in
# appsettings.json and in the registrations on the server; override with the environment if you
# renamed them.
first_https() { grep -o 'https://localhost:[0-9]\{2,5\}' "$1" 2>/dev/null | head -1; }

IDP_URL="${ARK_IDP_URL:-$(first_https "$HOST_PROJ/Properties/launchSettings.json")}"
APP_URL="${ARK_APP_URL:-$(first_https "$CLIENT_PROJ/Properties/launchSettings.json")}"
IDP_URL="${IDP_URL:-https://localhost:7233}"
APP_URL="${APP_URL:-https://localhost:7255}"

TENANT="${ARK_TENANT:-$(grep -o '"TenantId"[[:space:]]*:[[:space:]]*"[^"]*"' "$HOST_PROJ/appsettings.json" 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)"$/\1/')}"
TENANT="${TENANT:-ark_idp}"

WEB_CLIENT="${ARK_WEB_CLIENT_ID:-ark_sample_web}"       # ark_oauth_client:ClientId in Ark.Client.Web
SPA_CLIENT="${ARK_SPA_CLIENT_ID:-ark_sample_spa}"       # sample:Spa:ClientId      in Ark.Client.Web
MACHINE_CLIENT="${ARK_MACHINE_CLIENT_ID:-${TENANT}_machine}"  # seeded by the server on first run

ISSUER="$IDP_URL/$TENANT"
DISCOVERY="$ISSUER/.well-known/openid-configuration"
ADMIN_CONSOLE="$IDP_URL/$TENANT/admin"

# A fixed, valid S256 challenge (the RFC 7636 example). The readiness probes only need the
# authorization endpoint to accept the request far enough to prove the client is registered.
PROBE_CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

# --- Options ---------------------------------------------------------------------------------
DO_BUILD=1; OPEN_BROWSER=1; CHECK_ONLY=0; VERBOSE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)    DO_BUILD=0 ;;
        --no-browser)  OPEN_BROWSER=0 ;;
        --check-only)  CHECK_ONLY=1; DO_BUILD=0; OPEN_BROWSER=0 ;;
        --verbose|-v)  VERBOSE=1 ;;
        -h|--help)     awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)             echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

# --- Output ----------------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; N=$'\033[0m'
else
    B=""; DIM=""; RED=""; GRN=""; YEL=""; CYN=""; N=""
fi

step()  { printf '\n%s==>%s %s%s%s\n' "$CYN" "$N" "$B" "$*" "$N"; }
ok()    { printf '  %s✔%s %s\n' "$GRN" "$N" "$*"; }
warn()  { printf '  %s!%s %s\n' "$YEL" "$N" "$*"; }
bad()   { printf '  %s✘%s %s\n' "$RED" "$N" "$*"; }
hint()  { printf '      %s%s%s\n' "$DIM" "$*" "$N"; }
die()   { printf '\n%serror:%s %s\n' "$RED" "$N" "$*" >&2; exit 1; }

CURL=(curl --silent --insecure --max-time 10)

# --- Cleanup ---------------------------------------------------------------------------------
HOST_PID=""; CLIENT_PID=""
cleanup() {
    trap - INT TERM EXIT
    local pid
    # `dotnet run` forwards SIGTERM to the application it launched, so terminating it is enough;
    # pkill -P is a fallback for the case where it did not get that far.
    for pid in "$CLIENT_PID" "$HOST_PID"; do
        [ -n "$pid" ] || continue
        kill -TERM "$pid" 2>/dev/null
        pkill -TERM -P "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    [ -n "$HOST_PID$CLIENT_PID" ] && printf '\n%sstopped.%s\n' "$DIM" "$N"
    return 0
}
trap cleanup INT TERM EXIT

# =============================================================================================
# 1. Preflight
# =============================================================================================
preflight() {
    step "Checking prerequisites"

    command -v dotnet >/dev/null 2>&1 || die "the .NET SDK is not on PATH. Install .NET 9 or later: https://dotnet.microsoft.com/download"
    ok ".NET SDK $(dotnet --version)"

    command -v curl >/dev/null 2>&1 || die "curl is required for the readiness checks."

    if ! dotnet --list-runtimes 2>/dev/null | grep -q 'Microsoft\.AspNetCore\.App 9\.'; then
        warn "no ASP.NET Core 9 runtime found — both projects target net9.0."
        hint "install it, or run with DOTNET_ROLL_FORWARD=Major to use a newer runtime."
    fi

    # The sign-in redirect is https, so an untrusted development certificate stops the flow in
    # the browser rather than in either application.
    if dotnet dev-certs https --check --trust >/dev/null 2>&1; then
        ok "https development certificate is trusted"
    else
        warn "the https development certificate is missing or untrusted"
        hint "fix with:  dotnet dev-certs https --trust"
    fi

    # SQLite will not create the directory holding its database file.
    mkdir -p "$HOST_PROJ/data"

    if [ "$CHECK_ONLY" -eq 0 ]; then
        port_busy "$IDP_URL" && die "$IDP_URL is already in use — stop whatever is on that port, or run with --check-only to test it."
        port_busy "$APP_URL" && die "$APP_URL is already in use — stop whatever is on that port, or run with --check-only to test it."
        ok "ports free"
        admin_password
    fi
}

port_busy() {
    local port; port="${1##*:}"
    command -v lsof >/dev/null 2>&1 || return 1
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
}

# The administrator account is created once, when the database is first built, from
# ark_oauth_server:AdminUser. The password is required and has no default: with none configured
# the first request fails and no database is left behind. It is only read while the database is
# being created, so an existing data/ file means the account already exists and this is moot.
admin_username() {
    local u
    u=$(grep -A2 '"AdminUser"' "$HOST_PROJ/appsettings.json" 2>/dev/null \
        | grep -o '"Username"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
    printf '%s' "${u:-admin}"
}

admin_password() {
    if [ -f "$DB_FILE" ]; then
        ok "database exists — the admin account was seeded on a previous run"
        return 0
    fi

    if [ -n "${ark_oauth_server__AdminUser__Password:-}" ]; then
        ok "admin password supplied by the environment"
        return 0
    fi

    local configured
    configured=$(grep -A3 '"AdminUser"' "$HOST_PROJ/appsettings.json" | grep -o '"Password"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
    case "$configured" in
        ""|"<<"*) ;;                              # unset, or left as a <<placeholder>>
        *) ok "admin password configured in appsettings.json"; return 0 ;;
    esac

    printf '\n  %sThis is the first run: the database does not exist yet.%s\n' "$B" "$N"
    printf '  The administrator account is created now, once, and its password has no default.\n\n'

    if [ -t 0 ]; then
        local pw pw2
        read -r -s -p "  Choose a password for '$(admin_username)': " pw; echo
        read -r -s -p "  Repeat it: " pw2; echo
        [ -n "$pw" ]      || die "an empty password will not do."
        [ "$pw" = "$pw2" ] || die "the two entries did not match."
        export ark_oauth_server__AdminUser__Password="$pw"
        printf '\n'
        ok "password accepted — it seeds the account for this run only and is not written to disk"
        hint "note it down, then change it after the first sign-in."
    else
        die "no admin password configured. Set one before the first run:

    export ark_oauth_server__AdminUser__Password='a-real-password'
    ./run.sh

  or put it in user-secrets:

    dotnet user-secrets init --project $HOST_PROJ
    dotnet user-secrets set 'ark_oauth_server:AdminUser:Password' 'a-real-password' --project $HOST_PROJ"
    fi
}

# =============================================================================================
# 2. Build
# =============================================================================================
build() {
    [ "$DO_BUILD" -eq 1 ] || return 0
    step "Building"
    if [ "$VERBOSE" -eq 1 ]; then
        dotnet build "$SLN" --nologo || die "the build failed."
    else
        dotnet build "$SLN" --nologo -v quiet >"$LOG_DIR/build.log" 2>&1 \
            || { tail -30 "$LOG_DIR/build.log"; die "the build failed — full output in .run-logs/build.log"; }
    fi
    ok "solution built"
}

# =============================================================================================
# 3. Start a project and wait for it to answer
# =============================================================================================
start_project() {
    local name="$1" proj="$2" profile="$3" url="$4" probe="$5" log="$LOG_DIR/$3.log"

    step "Starting $name"
    ASPNETCORE_ENVIRONMENT=Development \
        dotnet run --project "$proj" --launch-profile "$profile" --no-build >"$log" 2>&1 &
    local pid=$!
    # Recorded before the wait loop, not after it — otherwise Ctrl-C during startup leaves an
    # untracked process holding the port.
    eval "$6=$pid"
    printf '  %s%s → %s (pid %s, log .run-logs/%s.log)%s\n' "$DIM" "$proj" "$url" "$pid" "$profile" "$N"

    local i code
    for i in $(seq 1 90); do
        if ! kill -0 "$pid" 2>/dev/null; then
            printf '\n'; tail -25 "$log"
            die "$name exited during startup — full output in .run-logs/$profile.log"
        fi
        code=$("${CURL[@]}" --max-time 2 -o /dev/null -w '%{http_code}' "$probe" 2>/dev/null)
        if [ "$code" = "200" ]; then
            ok "$name is up at $url"
            return 0
        fi
        sleep 1
    done

    printf '\n'; tail -25 "$log"
    die "$name did not answer at $probe within 90s."
}

# =============================================================================================
# 4. Readiness — is the end-to-end sample actually usable?
# =============================================================================================
READY=1
note_gap() { READY=0; }

# The authorization endpoint answers 200 (the sign-in page) for a registered client and 400 with
# "unknown client_id" for one that was never created. That distinction is the whole check, and it
# needs no credentials.
probe_client() {
    local client_id="$1" redirect="$2" body code
    body=$("${CURL[@]}" -w '\n%{http_code}' \
        "$ISSUER/oauth2/authorize?response_type=code&client_id=$client_id&redirect_uri=$redirect&scope=openid&state=probe&nonce=probe&code_challenge=$PROBE_CHALLENGE&code_challenge_method=S256" 2>/dev/null)
    code=$(printf '%s' "$body" | tail -1)
    if [ "$code" = "200" ]; then
        echo "registered"
    else
        printf '%s' "$body" | sed 's/<[^>]*>//g' | sed -e 's/^[[:space:]]*//' -e '/^$/d' \
            | awk "/complete that request/{getline; print; exit}" | head -1
    fi
}

urlenc() { printf '%s' "$1" | sed -e 's|:|%3A|g' -e 's|/|%2F|g'; }

check_readiness() {
    step "Checking the end-to-end sample"

    # -- the provider itself ------------------------------------------------------------------
    local disc issuer
    disc=$("${CURL[@]}" "$DISCOVERY" 2>/dev/null)
    if [ -z "$disc" ]; then
        bad "the discovery document at $DISCOVERY is not being served"
        note_gap; return
    fi
    issuer=$(printf '%s' "$disc" | sed -n 's/.*"issuer"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    if [ "$issuer" = "$ISSUER" ]; then
        ok "discovery served, issuer is $issuer"
    else
        bad "discovery reports issuer '$issuer', expected '$ISSUER'"
        hint "ark_oauth_server:BaseUrl must match the address the server is actually reached on."
        note_gap
    fi

    if "${CURL[@]}" "$ISSUER/.well-known/jwks.json" 2>/dev/null | grep -q '"kid"'; then
        ok "signing key published at /.well-known/jwks.json"
    else
        bad "no signing key at $ISSUER/.well-known/jwks.json"
        note_gap
    fi

    # -- the web sample -----------------------------------------------------------------------
    local result
    result=$(probe_client "$WEB_CLIENT" "$(urlenc "$APP_URL/signin-oidc")")
    if [ "$result" = "registered" ]; then
        ok "client '$WEB_CLIENT' is registered — the sign-in page renders"
    else
        bad "client '$WEB_CLIENT' is not usable: ${result:-the authorization endpoint refused the request}"
        hint "Register it at $ADMIN_CONSOLE → Clients:"
        hint "  client_id                   $WEB_CLIENT"
        hint "  redirect_uris               $APP_URL/signin-oidc"
        hint "  post_logout_redirect_uris   $APP_URL/signout-callback-oidc"
        hint "  token_endpoint_auth_method  none            (public client)"
        hint "  grant_types                 authorization_code refresh_token"
        hint "  scopes                      openid profile email offline_access"
        note_gap
    fi

    # -- the SPA sample -----------------------------------------------------------------------
    result=$(probe_client "$SPA_CLIENT" "$(urlenc "$APP_URL/flows/spa")")
    if [ "$result" = "registered" ]; then
        ok "client '$SPA_CLIENT' is registered — /flows/spa will work"
    else
        warn "client '$SPA_CLIENT' is not registered — /flows/spa will fail: ${result:-refused}"
        hint "Register it at $ADMIN_CONSOLE → Clients, or from $APP_URL/flows/register:"
        hint "  client_id                   $SPA_CLIENT"
        hint "  redirect_uris               $APP_URL/flows/spa"
        hint "  token_endpoint_auth_method  none            (public client)"
        hint "  grant_types                 authorization_code"
        hint "  scopes                      openid profile email   (no offline_access)"
    fi

    # -- CORS, which only the browser-side flow needs ------------------------------------------
    if "${CURL[@]}" -i -X OPTIONS "$ISSUER/oauth2/token" \
            -H "Origin: $APP_URL" -H "Access-Control-Request-Method: POST" \
            -H "Access-Control-Request-Headers: content-type" 2>/dev/null \
            | grep -qi "access-control-allow-origin: $APP_URL"; then
        ok "$APP_URL is allowed to call the token endpoint from the browser"
    else
        warn "$APP_URL is not in ark_oauth_server:Oidc:CorsOrigins — /flows/spa cannot redeem its code"
        hint "add it in $HOST_PROJ/appsettings.json and restart the provider."
    fi

    # -- the machine client, used by /flows/machine and /flows/register ------------------------
    local secret
    secret="${ARK_MACHINE_SECRET:-}"
    if [ -z "$secret" ]; then
        secret=$(dotnet user-secrets list --project "$CLIENT_PROJ" 2>/dev/null \
            | sed -n 's/^sample:Machine:ClientSecret = //p' | head -1)
    fi
    if [ -z "$secret" ]; then
        secret=$(grep -A3 '"Machine"' "$CLIENT_PROJ/appsettings.json" 2>/dev/null \
            | grep -o '"ClientSecret"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
    fi

    if [ -z "$secret" ]; then
        warn "no secret for '$MACHINE_CLIENT' — /flows/machine and /flows/register will fail"
        hint "$ADMIN_CONSOLE → Clients → $MACHINE_CLIENT → Regenerate secret, then:"
        hint "  dotnet user-secrets set 'sample:Machine:ClientSecret' '<secret>' --project $CLIENT_PROJ"
    elif "${CURL[@]}" -X POST "$ISSUER/oauth2/token" \
            -d "grant_type=client_credentials" -d "client_id=$MACHINE_CLIENT" \
            -d "client_secret=$secret" -d "scope=client.register" 2>/dev/null | grep -q '"access_token"'; then
        ok "'$MACHINE_CLIENT' can obtain a token — /flows/machine and /flows/register will work"
    else
        warn "the configured secret for '$MACHINE_CLIENT' was rejected"
        hint "regenerate it in the console and store the new value in user-secrets."
    fi
}

# =============================================================================================
# 5. Summary
# =============================================================================================
summary() {
    local admin_user
    admin_user=$(admin_username)

    printf '\n%s─────────────────────────────────────────────────────────────────────────%s\n' "$DIM" "$N"
    printf '  %sIdentity provider%s   %s\n'   "$B" "$N" "$IDP_URL"
    printf '  %sIssuer%s              %s\n'   "$B" "$N" "$ISSUER"
    printf '  %sDiscovery%s           %s\n'   "$B" "$N" "$DISCOVERY"
    printf '  %sAdmin console%s       %s\n'   "$B" "$N" "$ADMIN_CONSOLE"
    printf '  %sSample client%s       %s\n'   "$B" "$N" "$APP_URL"
    printf '  %sSign in as%s          %s\n'   "$B" "$N" "${admin_user:-admin} (the password set on the first run)"
    printf '%s─────────────────────────────────────────────────────────────────────────%s\n' "$DIM" "$N"

    if [ "$READY" -eq 1 ]; then
        printf '\n  %sReady.%s Open %s and press Sign in.\n' "$GRN" "$N" "$APP_URL"
    else
        printf '\n  %sOne step left.%s Fix the ✘ above at %s, then re-run with --check-only.\n' "$YEL" "$N" "$ADMIN_CONSOLE"
    fi

    # Access mapping cannot be probed without signing in, and its absence looks exactly like a
    # wrong password — so it is always worth naming.
    printf '\n  %sIf sign-in says the credentials are not recognised and they are correct:%s\n' "$DIM" "$N"
    printf '  %sthat is a missing Access mapping — %s → Access mapping → user + client + claims.%s\n\n' "$DIM" "$ADMIN_CONSOLE" "$N"
}

# =============================================================================================
main() {
    mkdir -p "$LOG_DIR"
    printf '%s%sArk Identity Server — local end-to-end%s\n' "$B" "$CYN" "$N"

    preflight
    build

    if [ "$CHECK_ONLY" -eq 1 ]; then
        step "Check only — not starting anything"
        check_readiness
        summary
        trap - INT TERM EXIT
        [ "$READY" -eq 1 ] && exit 0 || exit 1
    fi

    start_project "the identity provider" "$HOST_PROJ" "Ark.oAuth.Oidc.Host" "$IDP_URL" "$DISCOVERY" HOST_PID
    check_readiness
    start_project "the sample client" "$CLIENT_PROJ" "Ark.Client.Web" "$APP_URL" "$APP_URL/" CLIENT_PID

    summary

    if [ "$OPEN_BROWSER" -eq 1 ] && command -v open >/dev/null 2>&1; then
        open "$APP_URL" 2>/dev/null
    elif [ "$OPEN_BROWSER" -eq 1 ] && command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$APP_URL" >/dev/null 2>&1
    fi

    printf '  %sBoth running. Ctrl-C to stop. Logs: .run-logs/%s\n\n' "$DIM" "$N"
    wait
}

main
