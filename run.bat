@echo off
rem ============================================================================================
rem  Ark Identity Server - start the whole sample end to end.  (Windows; run.sh is the macOS/Linux twin)
rem
rem    1. checks you have what you need (SDK, trusted dev certificate, free ports, admin password)
rem    2. builds the solution
rem    3. starts Ark.oAuth.Oidc.Host   - the identity provider  (https://localhost:7233)
rem    4. waits for its discovery document, then verifies the sample registrations exist
rem    5. starts Ark.Client.Web        - the sample client      (https://localhost:7255)
rem    6. prints what is ready, what is not, and the exact fix for anything missing
rem
rem  Each application gets its own console window, so its log is in front of you. Close both
rem  windows to stop, or run:  run.bat --stop
rem
rem  Usage:  run.bat [--no-build] [--no-browser] [--check-only] [--stop] [--verbose]
rem
rem  See GETTINGSTARTED.md for what every check means.
rem ============================================================================================
setlocal EnableDelayedExpansion

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "SLN_DIR=%ROOT%\Ark.oAuth.Oidc"
set "SLN=%SLN_DIR%\Ark.oAuth.Oidc.sln"
set "HOST_PROJ=%SLN_DIR%\Ark.oAuth.Oidc.Host"
set "CLIENT_PROJ=%SLN_DIR%\Ark.Client.Web"
set "DB_FILE=%HOST_PROJ%\data\ark_idp.db"
set "TMPD=%TEMP%\ark-run"
if not exist "%TMPD%" mkdir "%TMPD%" >nul 2>&1

rem --- Addresses -------------------------------------------------------------------------------
rem  These mirror the two launchSettings.json files and the appsettings.json of each project.
rem  If you change a port there, change it here too - the script warns below when they disagree.
rem  Anything here can be overridden from the environment before calling.
if not defined ARK_IDP_URL          set "ARK_IDP_URL=https://localhost:7233"
if not defined ARK_APP_URL          set "ARK_APP_URL=https://localhost:7255"
if not defined ARK_TENANT           set "ARK_TENANT=ark_idp"
if not defined ARK_WEB_CLIENT_ID    set "ARK_WEB_CLIENT_ID=ark_sample_web"
if not defined ARK_SPA_CLIENT_ID    set "ARK_SPA_CLIENT_ID=ark_sample_spa"
if not defined ARK_MACHINE_CLIENT_ID set "ARK_MACHINE_CLIENT_ID=%ARK_TENANT%_machine"

set "IDP_URL=%ARK_IDP_URL%"
set "APP_URL=%ARK_APP_URL%"
set "TENANT=%ARK_TENANT%"
set "WEB_CLIENT=%ARK_WEB_CLIENT_ID%"
set "SPA_CLIENT=%ARK_SPA_CLIENT_ID%"
set "MACHINE_CLIENT=%ARK_MACHINE_CLIENT_ID%"

set "ISSUER=%IDP_URL%/%TENANT%"
set "DISCOVERY=%ISSUER%/.well-known/openid-configuration"
set "ADMIN_CONSOLE=%ISSUER%/admin"

rem A fixed, valid S256 challenge (the RFC 7636 example). The readiness probes only need the
rem authorization endpoint to accept the request far enough to prove the client is registered.
set "PROBE_CHALLENGE=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

set "IDP_WINDOW=Ark identity provider"
set "APP_WINDOW=Ark sample client"

rem --- Options ---------------------------------------------------------------------------------
set "DO_BUILD=1"
set "OPEN_BROWSER=1"
set "CHECK_ONLY=0"
set "VERBOSE=0"

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="--no-build"   ( set "DO_BUILD=0" & shift & goto parse )
if /i "%~1"=="--no-browser" ( set "OPEN_BROWSER=0" & shift & goto parse )
if /i "%~1"=="--check-only" ( set "CHECK_ONLY=1" & set "DO_BUILD=0" & set "OPEN_BROWSER=0" & shift & goto parse )
if /i "%~1"=="--verbose"    ( set "VERBOSE=1" & shift & goto parse )
if /i "%~1"=="--stop"       goto stop_all
if /i "%~1"=="-h"           goto usage
if /i "%~1"=="--help"       goto usage
echo unknown option: %~1  (try --help)
exit /b 2
:parsed

set "READY=1"

echo.
echo Ark Identity Server - local end-to-end
echo.

call :preflight        || exit /b 1
call :build            || exit /b 1
if "%CHECK_ONLY%"=="1" (
    echo.
    echo ==^> Check only - not starting anything
    call :check_readiness
    call :summary
    if "!READY!"=="1" ( exit /b 0 ) else ( exit /b 1 )
)

call :start_app "%IDP_WINDOW%"  "%HOST_PROJ%"   "Ark.oAuth.Oidc.Host" "%DISCOVERY%" || exit /b 1
call :check_readiness
call :start_app "%APP_WINDOW%"  "%CLIENT_PROJ%" "Ark.Client.Web"      "%APP_URL%/"  || exit /b 1
call :summary

if "%OPEN_BROWSER%"=="1" start "" "%APP_URL%"

echo   Both windows are running. Close them, or run "run.bat --stop", to stop.
echo.
exit /b 0


rem =============================================================================================
rem  1. Preflight
rem =============================================================================================
:preflight
echo ==^> Checking prerequisites

where dotnet >nul 2>&1
if errorlevel 1 (
    echo   [X] the .NET SDK is not on PATH. Install .NET 9 or later:
    echo       https://dotnet.microsoft.com/download
    exit /b 1
)
for /f "delims=" %%V in ('dotnet --version 2^>nul') do set "SDKVER=%%V"
echo   [ok] .NET SDK !SDKVER!

where curl >nul 2>&1
if errorlevel 1 (
    echo   [X] curl.exe was not found. It ships with Windows 10 1803 and later;
    echo       on an older build, install curl or use run.sh under WSL.
    exit /b 1
)

dotnet --list-runtimes 2>nul | findstr /r /c:"Microsoft.AspNetCore.App 9\." >nul
if errorlevel 1 (
    echo   [warn] no ASP.NET Core 9 runtime found - both projects target net9.0.
    echo       install it, or set DOTNET_ROLL_FORWARD=Major to use a newer runtime.
)

rem The sign-in redirect is https, so an untrusted development certificate stops the flow in the
rem browser rather than in either application.
dotnet dev-certs https --check --trust >nul 2>&1
if errorlevel 1 (
    echo   [warn] the https development certificate is missing or untrusted
    echo       fix with:  dotnet dev-certs https --trust
) else (
    echo   [ok] https development certificate is trusted
)

rem SQLite will not create the directory holding its database file.
if not exist "%HOST_PROJ%\data" mkdir "%HOST_PROJ%\data" >nul 2>&1

rem Warn if the addresses above have drifted from what the projects actually listen on.
findstr /c:"%IDP_URL%" "%HOST_PROJ%\Properties\launchSettings.json" >nul 2>&1
if errorlevel 1 echo   [warn] %IDP_URL% is not in Ark.oAuth.Oidc.Host\Properties\launchSettings.json - edit ARK_IDP_URL at the top of this script
findstr /c:"%APP_URL%" "%CLIENT_PROJ%\Properties\launchSettings.json" >nul 2>&1
if errorlevel 1 echo   [warn] %APP_URL% is not in Ark.Client.Web\Properties\launchSettings.json - edit ARK_APP_URL at the top of this script

if "%CHECK_ONLY%"=="1" exit /b 0

call :port_busy "%IDP_URL%"
if not errorlevel 1 (
    echo   [X] %IDP_URL% is already in use - stop whatever is on that port,
    echo       or run "run.bat --check-only" to test what is already running.
    exit /b 1
)
call :port_busy "%APP_URL%"
if not errorlevel 1 (
    echo   [X] %APP_URL% is already in use - stop whatever is on that port,
    echo       or run "run.bat --check-only" to test what is already running.
    exit /b 1
)
echo   [ok] ports free

call :admin_password || exit /b 1
exit /b 0

rem Returns 0 (success) when the port IS in use.
:port_busy
set "_URL=%~1"
for /f "tokens=3 delims=:" %%P in ("%_URL%") do set "_PORT=%%P"
netstat -ano -p tcp | findstr /r /c:":%_PORT% .*LISTENING" >nul 2>&1
exit /b %errorlevel%

rem The administrator account is created once, when the database is first built, from
rem ark_oauth_server:AdminUser. The password is required and has no default: with none configured
rem the first request fails and no database is left behind. It is only read while the database is
rem being created, so an existing data file means the account already exists and this is moot.
:admin_password
if exist "%DB_FILE%" (
    echo   [ok] database exists - the admin account was seeded on a previous run
    exit /b 0
)
if defined ark_oauth_server__AdminUser__Password (
    echo   [ok] admin password supplied by the environment
    exit /b 0
)

rem An unset password, or one still left as a ^<^<placeholder^>^>, both count as unset.
set "CONFIGURED="
for /f "tokens=2 delims=:" %%A in ('findstr /c:"\"Password\"" "%HOST_PROJ%\appsettings.json" 2^>nul') do (
    if not defined CONFIGURED set "CONFIGURED=%%A"
)
if defined CONFIGURED (
    set "CONFIGURED=!CONFIGURED: =!"
    set "CONFIGURED=!CONFIGURED:"=!"
    set "CONFIGURED=!CONFIGURED:,=!"
    if not "!CONFIGURED!"=="" if not "!CONFIGURED:~0,2!"=="<<" (
        echo   [ok] admin password configured in appsettings.json
        exit /b 0
    )
)

echo.
echo   This is the first run: the database does not exist yet.
echo   The administrator account is created now, once, and its password has no default.
echo.

rem Read it without echoing to the screen. PowerShell is used only for the hidden prompt; the
rem value is exported to the child process and never written to disk.
for /f "usebackq delims=" %%P in (`powershell -NoProfile -Command "$s = Read-Host -AsSecureString 'Choose a password for the admin account'; [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))"`) do set "ADMINPW=%%P"

if not defined ADMINPW (
    echo.
    echo   [X] no admin password configured. Set one before the first run:
    echo.
    echo       set ark_oauth_server__AdminUser__Password=a-real-password
    echo       run.bat
    echo.
    echo     or put it in user-secrets:
    echo.
    echo       dotnet user-secrets init --project "%HOST_PROJ%"
    echo       dotnet user-secrets set "ark_oauth_server:AdminUser:Password" "a-real-password" --project "%HOST_PROJ%"
    exit /b 1
)
set "ark_oauth_server__AdminUser__Password=%ADMINPW%"
set "ADMINPW="
echo.
echo   [ok] password accepted - it seeds the account for this run only and is not written to disk
echo        note it down, then change it after the first sign-in.
exit /b 0


rem =============================================================================================
rem  2. Build
rem =============================================================================================
:build
if "%DO_BUILD%"=="0" exit /b 0
echo.
echo ==^> Building
if "%VERBOSE%"=="1" (
    dotnet build "%SLN%" --nologo
) else (
    dotnet build "%SLN%" --nologo -v quiet > "%TMPD%\build.log" 2>&1
)
if errorlevel 1 (
    if "%VERBOSE%"=="0" type "%TMPD%\build.log"
    echo   [X] the build failed.
    exit /b 1
)
echo   [ok] solution built
exit /b 0


rem =============================================================================================
rem  3. Start a project in its own window and wait for it to answer
rem =============================================================================================
:start_app
set "_TITLE=%~1"
set "_PROJ=%~2"
set "_PROFILE=%~3"
set "_PROBE=%~4"
echo.
echo ==^> Starting %_TITLE%
start "%_TITLE%" cmd /k "set ASPNETCORE_ENVIRONMENT=Development&& dotnet run --project "%_PROJ%" --launch-profile %_PROFILE% --no-build"

set /a _TRIES=0
:wait_loop
set /a _TRIES+=1
call :http_code "%_PROBE%"
if "!HTTP_CODE!"=="200" (
    echo   [ok] %_TITLE% is up
    exit /b 0
)
if !_TRIES! geq 90 (
    echo   [X] %_TITLE% did not answer at %_PROBE% within 90s.
    echo       Look at the "%_TITLE%" window for the reason.
    exit /b 1
)
timeout /t 1 /nobreak >nul
goto wait_loop

rem Sets HTTP_CODE to the status of a GET, or 000 if the request did not complete.
:http_code
curl -s -k --max-time 3 -o "%TMPD%\body.txt" -w "%%{http_code}" "%~1" > "%TMPD%\code.txt" 2>nul
set "HTTP_CODE=000"
if exist "%TMPD%\code.txt" set /p HTTP_CODE=<"%TMPD%\code.txt"
exit /b 0


rem =============================================================================================
rem  4. Readiness - is the end-to-end sample actually usable?
rem =============================================================================================
:check_readiness
echo.
echo ==^> Checking the end-to-end sample

rem -- the provider itself ----------------------------------------------------------------------
call :http_code "%DISCOVERY%"
if not "!HTTP_CODE!"=="200" (
    echo   [X] the discovery document at %DISCOVERY% is not being served
    set "READY=0"
    exit /b 0
)
findstr /c:"\"issuer\":\"%ISSUER%\"" "%TMPD%\body.txt" >nul 2>&1
if errorlevel 1 findstr /c:"\"issuer\": \"%ISSUER%\"" "%TMPD%\body.txt" >nul 2>&1
if errorlevel 1 (
    echo   [X] discovery does not report the issuer %ISSUER%
    echo       ark_oauth_server:BaseUrl must match the address the server is actually reached on.
    set "READY=0"
) else (
    echo   [ok] discovery served, issuer is %ISSUER%
)

call :http_code "%ISSUER%/.well-known/jwks.json"
findstr /c:"kid" "%TMPD%\body.txt" >nul 2>&1
if errorlevel 1 (
    echo   [X] no signing key at %ISSUER%/.well-known/jwks.json
    set "READY=0"
) else (
    echo   [ok] signing key published at /.well-known/jwks.json
)

rem -- the web sample ---------------------------------------------------------------------------
rem The authorization endpoint answers 200 (the sign-in page) for a registered client and 400 for
rem one that was never created. That distinction is the whole check, and it needs no credentials.
call :probe_client "%WEB_CLIENT%" "%APP_URL%/signin-oidc"
if "!HTTP_CODE!"=="200" (
    echo   [ok] client '%WEB_CLIENT%' is registered - the sign-in page renders
) else (
    echo   [X] client '%WEB_CLIENT%' is not usable - the authorization endpoint refused the request
    echo       Register it at %ADMIN_CONSOLE% -^> Clients:
    echo         client_id                   %WEB_CLIENT%
    echo         redirect_uris               %APP_URL%/signin-oidc
    echo         post_logout_redirect_uris   %APP_URL%/signout-callback-oidc
    echo         token_endpoint_auth_method  none            ^(public client^)
    echo         grant_types                 authorization_code refresh_token
    echo         scopes                      openid profile email offline_access
    set "READY=0"
)

rem -- the SPA sample ---------------------------------------------------------------------------
call :probe_client "%SPA_CLIENT%" "%APP_URL%/flows/spa"
if "!HTTP_CODE!"=="200" (
    echo   [ok] client '%SPA_CLIENT%' is registered - /flows/spa will work
) else (
    echo   [warn] client '%SPA_CLIENT%' is not registered - /flows/spa will fail
    echo       Register it at %ADMIN_CONSOLE% -^> Clients, or from %APP_URL%/flows/register:
    echo         client_id                   %SPA_CLIENT%
    echo         redirect_uris               %APP_URL%/flows/spa
    echo         token_endpoint_auth_method  none            ^(public client^)
    echo         grant_types                 authorization_code
    echo         scopes                      openid profile email   ^(no offline_access^)
)

rem -- CORS, which only the browser-side flow needs ---------------------------------------------
curl -s -k --max-time 5 -i -X OPTIONS "%ISSUER%/oauth2/token" -H "Origin: %APP_URL%" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: content-type" -o "%TMPD%\cors.txt" >nul 2>&1
findstr /i /c:"access-control-allow-origin: %APP_URL%" "%TMPD%\cors.txt" >nul 2>&1
if errorlevel 1 (
    echo   [warn] %APP_URL% is not in ark_oauth_server:Oidc:CorsOrigins - /flows/spa cannot redeem its code
    echo       add it in Ark.oAuth.Oidc.Host\appsettings.json and restart the provider.
) else (
    echo   [ok] %APP_URL% is allowed to call the token endpoint from the browser
)

rem -- the machine client, used by /flows/machine and /flows/register ----------------------------
call :machine_secret
if not defined MSECRET (
    echo   [warn] no secret for '%MACHINE_CLIENT%' - /flows/machine and /flows/register will fail
    echo       %ADMIN_CONSOLE% -^> Clients -^> %MACHINE_CLIENT% -^> Regenerate secret, then:
    echo         dotnet user-secrets set "sample:Machine:ClientSecret" "^<secret^>" --project "%CLIENT_PROJ%"
    exit /b 0
)
curl -s -k --max-time 8 -X POST "%ISSUER%/oauth2/token" -d "grant_type=client_credentials" -d "client_id=%MACHINE_CLIENT%" -d "client_secret=!MSECRET!" -d "scope=client.register" -o "%TMPD%\tok.txt" >nul 2>&1
findstr /c:"access_token" "%TMPD%\tok.txt" >nul 2>&1
if errorlevel 1 (
    echo   [warn] the configured secret for '%MACHINE_CLIENT%' was rejected
    echo       regenerate it in the console and store the new value in user-secrets.
) else (
    echo   [ok] '%MACHINE_CLIENT%' can obtain a token - /flows/machine and /flows/register will work
)
exit /b 0

rem Sets HTTP_CODE from an authorization request for the given client and redirect URI.
:probe_client
set "_CID=%~1"
set "_RURI=%~2"
set "_RURI=!_RURI::=%%3A!"
set "_RURI=!_RURI:/=%%2F!"
set "_URL=%ISSUER%/oauth2/authorize?response_type=code&client_id=!_CID!&redirect_uri=!_RURI!&scope=openid&state=probe&nonce=probe&code_challenge=%PROBE_CHALLENGE%&code_challenge_method=S256"
call :http_code "!_URL!"
exit /b 0

rem The secret for the seeded machine client: the environment first, then user-secrets, then
rem appsettings.json (where only the sample's Machine section has a quoted ClientSecret).
:machine_secret
set "MSECRET="
if defined ARK_MACHINE_SECRET (
    set "MSECRET=%ARK_MACHINE_SECRET%"
    exit /b 0
)
for /f "tokens=2 delims== " %%S in ('dotnet user-secrets list --project "%CLIENT_PROJ%" 2^>nul ^| findstr /c:"sample:Machine:ClientSecret"') do set "MSECRET=%%S"
if defined MSECRET exit /b 0
for /f "tokens=2 delims=:" %%S in ('findstr /c:"\"ClientSecret\": \"" "%CLIENT_PROJ%\appsettings.json" 2^>nul') do (
    if not defined MSECRET set "MSECRET=%%S"
)
if defined MSECRET (
    set "MSECRET=!MSECRET: =!"
    set "MSECRET=!MSECRET:"=!"
    set "MSECRET=!MSECRET:,=!"
)
exit /b 0


rem =============================================================================================
rem  5. Summary
rem =============================================================================================
:summary
set "ADMIN_USER="
for /f "tokens=2 delims=:" %%A in ('findstr /c:"\"Username\"" "%HOST_PROJ%\appsettings.json" 2^>nul') do (
    if not defined ADMIN_USER set "ADMIN_USER=%%A"
)
if defined ADMIN_USER (
    for /f "tokens=1 delims=," %%B in ("!ADMIN_USER!") do set "ADMIN_USER=%%B"
    set "ADMIN_USER=!ADMIN_USER: =!"
    set "ADMIN_USER=!ADMIN_USER:"=!"
)
if not defined ADMIN_USER set "ADMIN_USER=admin"

echo.
echo  -----------------------------------------------------------------------
echo   Identity provider   %IDP_URL%
echo   Issuer              %ISSUER%
echo   Discovery           %DISCOVERY%
echo   Admin console       %ADMIN_CONSOLE%
echo   Sample client       %APP_URL%
echo   Sign in as          !ADMIN_USER! ^(the password set on the first run^)
echo  -----------------------------------------------------------------------
echo.
if "%READY%"=="1" (
    echo   Ready. Open %APP_URL% and press Sign in.
) else (
    echo   One step left. Fix the [X] above at %ADMIN_CONSOLE%,
    echo   then re-run with:  run.bat --check-only
)
echo.
rem Access mapping cannot be probed without signing in, and its absence looks exactly like a
rem wrong password - so it is always worth naming.
echo   If sign-in says the credentials are not recognised and they are correct:
echo   that is a missing Access mapping - %ADMIN_CONSOLE% -^> Access mapping
echo   -^> user + client + claims.
echo.
exit /b 0


rem =============================================================================================
:stop_all
echo Stopping...
taskkill /F /T /FI "WINDOWTITLE eq %IDP_WINDOW%*" >nul 2>&1
taskkill /F /T /FI "WINDOWTITLE eq %APP_WINDOW%*" >nul 2>&1
echo Done. ^(Any window that stayed open can simply be closed.^)
exit /b 0

:usage
echo Usage:  run.bat [--no-build] [--no-browser] [--check-only] [--stop] [--verbose]
echo.
echo   --no-build     skip "dotnet build" and run what is already compiled
echo   --no-browser   do not open the sample client when it is ready
echo   --check-only   verify an already-running pair; start nothing
echo   --stop         close the two application windows this script opened
echo   --verbose      show full build output
echo.
echo See GETTINGSTARTED.md for what each readiness check means.
exit /b 0
