// Load generator for the Ark IdP: real authorization-code + PKCE sign-ins through the HTML form,
// then a mix of single sign-on, refresh, UserInfo, pushed authorization requests, the device flow,
// sign-out with back-channel logout, and the legacy v1 flow over the signed-in population.
//
// For a scratch provider seeded by ../seed.py only. It signs in as thousands of accounts and
// leaves their sessions and tokens behind; never point it at a provider anyone uses.
// See ../README.md for the options.
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

var opt = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
for (var i = 0; i < args.Length - 1; i += 2) opt[args[i].TrimStart('-')] = args[i + 1];
string Opt(string k, string d) => opt.TryGetValue(k, out var v) ? v : d;

var baseUrl = Opt("base", "http://127.0.0.1:5391").TrimEnd('/');
var tenant = Opt("tenant", "ark_idp");
var users = int.Parse(Opt("users", "1000"));
var offset = int.Parse(Opt("offset", "1"));
var conc = int.Parse(Opt("concurrency", "64"));
var steadySeconds = int.Parse(Opt("steady", "30"));
var steadyConc = int.Parse(Opt("steady-concurrency", conc.ToString()));
// No defaults for either credential: they are whatever seed.py was given, and a credential
// written into a public repository is one somebody will eventually find in use.
var password = Opt("password", Environment.GetEnvironmentVariable("LOADTEST_PASSWORD") ?? "");
var clientKind = Opt("client", "web"); // web = confidential (client_secret_post), spa = public
var label = Opt("label", "run");
var rate = double.Parse(Opt("rate", "0"));               // operations a second at full population; 0 = as fast as possible
var arrivalRate = double.Parse(Opt("arrival-rate", "0")); // sign-ins a second; 0 = everyone signs in first, --concurrency at a time
var bases = Opt("bases", "");                             // more instances of the same provider, comma separated
var insecure = Opt("insecure", "false") == "true";        // accept any TLS certificate (a development certificate)
var mixSpec = Opt("mix", "sso=40,refresh=30,userinfo=30");
var bclPort = int.Parse(Opt("bcl-port", "0"));            // listen here for back-channel logout tokens
var windowSeconds = int.Parse(Opt("window", "60"));
// Real users each bring their own connection. A small pool here makes slow requests (a sign-in waiting
// its turn to be hashed) hold connections that quick ones then queue for inside this process, and that
// wait is reported as the provider's response time when it is not.
var maxConnections = int.Parse(Opt("max-connections", "8192"));
var connectionSeconds = int.Parse(Opt("connection-lifetime", "300")); // a browser keeps its connection for minutes
var outFile = Opt("out", "");

var clientId = clientKind == "spa" ? "load_spa" : "load_web";
var clientSecret = clientKind == "spa" ? null : Opt("client-secret", Environment.GetEnvironmentVariable("LOADTEST_CLIENT_SECRET") ?? "");
if (password.Length == 0 || clientSecret == "")
{
    Console.Error.WriteLine("Pass --password (and --client-secret for --client web), or set LOADTEST_PASSWORD / LOADTEST_CLIENT_SECRET: the values seed.py was run with.");
    return 2;
}
var redirect = clientKind == "spa" ? "http://127.0.0.1:9/spa" : "http://127.0.0.1:9/cb";
var issuer = $"{baseUrl}/{tenant}";
// Several instances behind one public address: the issuer stays the first, each request is sent to the next in turn.
var instances = new[] { baseUrl }.Concat(bases.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(b => b.Trim().TrimEnd('/'))).ToArray();
var turn = -1;

var mix = mixSpec.Split(',', StringSplitOptions.RemoveEmptyEntries)
    .Select(p => p.Split('=')).Select(p => (op: p[0].Trim(), weight: int.Parse(p[1]))).Where(p => p.weight > 0).ToArray();
var mixTotal = mix.Sum(m => m.weight);
if (clientKind == "spa" && mix.Any(m => m.op is "par" or "v1"))
{
    Console.Error.WriteLine("par and v1 need the confidential client: use --client web.");
    return 2;
}

var handler = new SocketsHttpHandler
{
    UseCookies = false, AllowAutoRedirect = false,
    MaxConnectionsPerServer = maxConnections,
    // Recycled now and then, so a load balancer in front keeps re-spreading them.
    PooledConnectionLifetime = TimeSpan.FromSeconds(connectionSeconds),
    AutomaticDecompression = DecompressionMethods.None
};
if (insecure) handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };

// ---------------------------------------------------------------- measurements
var stats = new ConcurrentDictionary<string, ConcurrentBag<double>>();
var window = new ConcurrentDictionary<string, ConcurrentBag<double>>();
var errors = new ConcurrentDictionary<string, int>();
long windowErrors = 0, expired = 0, logoutTokens = 0, shed = 0, operations = 0;
// How late this process's own timers fire. If the generator itself stalls (a collection, a starved
// thread pool), every response time it reports is inflated by that much; a stall measured here is
// the generator's, not the provider's.
long lagMs = 0;
_ = Task.Run(async () =>
{
    while (true)
    {
        var t0 = Stopwatch.GetTimestamp();
        await Task.Delay(100);
        var late = (long)Stopwatch.GetElapsedTime(t0).TotalMilliseconds - 100;
        long seen;
        while (late > (seen = Interlocked.Read(ref lagMs)) && Interlocked.CompareExchange(ref lagMs, late, seen) != seen) { }
    }
});
void Rec(string step, double ms)
{
    stats.GetOrAdd(step, _ => new()).Add(ms);
    window.GetOrAdd(step, _ => new()).Add(ms);
}
void Err(string what)
{
    errors.AddOrUpdate(what, 1, (_, c) => c + 1);
    Interlocked.Increment(ref windowErrors);
}

var tokenRe = new Regex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"", RegexOptions.Compiled);
var scopeRe = new Regex("name=\"scope\" value=\"([^\"]+)\"", RegexOptions.Compiled);
var alertRe = new Regex("ark-alert.*?<span>([^<]*)</span>", RegexOptions.Compiled | RegexOptions.Singleline);

static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
static string Trunc(string s) => (s.Length > 90 ? s[..90] : s).Replace('\n', ' ').Trim();
static (string verifier, string challenge) Pkce()
{
    var verifier = B64Url(RandomNumberGenerator.GetBytes(40));
    return (verifier, B64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
}

string CookieHeader(Dictionary<string, string> jar) => string.Join("; ", jar.Select(kv => $"{kv.Key}={kv.Value}"));

HttpRequestMessage Req(HttpMethod method, string url, Dictionary<string, string>? jar = null, HttpContent? content = null)
{
    var req = new HttpRequestMessage(method, url) { Content = content };
    if (jar != null && jar.Count > 0) req.Headers.TryAddWithoutValidation("Cookie", CookieHeader(jar));
    return req;
}
FormUrlEncodedContent Form(params (string, string)[] fields) =>
    new(fields.Select(f => new KeyValuePair<string, string>(f.Item1, f.Item2)));

async Task<(HttpResponseMessage resp, string body)> Send(string step, HttpRequestMessage req)
{
    if (instances.Length > 1)
    {
        var target = instances[(int)((uint)Interlocked.Increment(ref turn) % (uint)instances.Length)];
        req.RequestUri = new Uri(target + req.RequestUri!.PathAndQuery);
    }
    var sw = Stopwatch.GetTimestamp();
    var resp = await http.SendAsync(req);
    var body = await resp.Content.ReadAsStringAsync();
    Rec(step, Stopwatch.GetElapsedTime(sw).TotalMilliseconds);
    return (resp, body);
}

void TakeCookies(HttpResponseMessage resp, Dictionary<string, string> jar)
{
    if (!resp.Headers.TryGetValues("Set-Cookie", out var values)) return;
    foreach (var v in values)
    {
        var first = v.Split(';')[0];
        var eq = first.IndexOf('=');
        if (eq <= 0) continue;
        var name = first[..eq]; var val = first[(eq + 1)..];
        if (val.Length == 0) jar.Remove(name); else jar[name] = val;
    }
}

string AuthorizeUrl(string challenge, string state) =>
    $"{issuer}/oauth2/authorize?client_id={clientId}&response_type=code&redirect_uri={Uri.EscapeDataString(redirect)}" +
    $"&scope={Uri.EscapeDataString("openid profile email offline_access")}&state={state}&nonce={state}" +
    $"&code_challenge={challenge}&code_challenge_method=S256";

bool IsSignInPage(HttpResponseMessage r, string body) => r.StatusCode == HttpStatusCode.OK && body.Contains("name=\"password\"");

void TakeTokens(VUser u, string body)
{
    using var doc = JsonDocument.Parse(body);
    u.AccessToken = doc.RootElement.GetProperty("access_token").GetString();
    if (doc.RootElement.TryGetProperty("refresh_token", out var rt)) u.RefreshToken = rt.GetString();
    if (doc.RootElement.TryGetProperty("id_token", out var it)) u.IdToken = it.GetString();
}

async Task<bool> Redeem(VUser u, string location, string verifier, string prefix)
{
    var q = System.Web.HttpUtility.ParseQueryString(new Uri(location).Query);
    var code = q["code"];
    if (string.IsNullOrEmpty(code)) { Err($"{prefix}:no_code:{q["error"]}:{q["error_description"]}"); return false; }
    var form = new Dictionary<string, string>
    {
        ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = redirect,
        ["code_verifier"] = verifier, ["client_id"] = clientId
    };
    if (clientSecret != null) form["client_secret"] = clientSecret;
    var (resp, body) = await Send($"{prefix}.token", new HttpRequestMessage(HttpMethod.Post, $"{issuer}/oauth2/token") { Content = new FormUrlEncodedContent(form) });
    if (resp.StatusCode != HttpStatusCode.OK) { Err($"{prefix}:token:{(int)resp.StatusCode}:{Trunc(body)}"); return false; }
    TakeTokens(u, body);
    if (u.IdToken == null) Err($"{prefix}:no_id_token");
    return true;
}

// ---------------------------------------------------------------- the flows
async Task<bool> SignIn(VUser u, string name = "signin")
{
    var total = Stopwatch.GetTimestamp();
    var (verifier, challenge) = Pkce();
    var url = AuthorizeUrl(challenge, B64Url(RandomNumberGenerator.GetBytes(12)));
    var jar = u.Cookies;
    jar.Remove("ark_idp_sid");

    var (r1, b1) = await Send($"{name}.page", Req(HttpMethod.Get, url, jar));
    TakeCookies(r1, jar);
    if (r1.StatusCode != HttpStatusCode.OK) { Err($"{name}:page:{(int)r1.StatusCode}"); return false; }
    var m = tokenRe.Match(b1);
    if (!m.Success) { Err($"{name}:no_csrf"); return false; }

    var (r2, b2) = await Send($"{name}.post", Req(HttpMethod.Post, url, jar, Form(
        ("ark_action", "signin"), ("username", u.Email), ("password", password),
        ("__RequestVerificationToken", WebUtility.HtmlDecode(m.Groups[1].Value)))));
    TakeCookies(r2, jar);

    if (r2.StatusCode == HttpStatusCode.OK && b2.Contains("value=\"consent\""))
    {
        var consent = new List<KeyValuePair<string, string>> { new("ark_action", "consent"), new("__RequestVerificationToken", WebUtility.HtmlDecode(tokenRe.Match(b2).Groups[1].Value)) };
        foreach (Match s in scopeRe.Matches(b2)) consent.Add(new("scope", WebUtility.HtmlDecode(s.Groups[1].Value)));
        (r2, b2) = await Send($"{name}.consent", Req(HttpMethod.Post, url, jar, new FormUrlEncodedContent(consent)));
        TakeCookies(r2, jar);
    }
    if (r2.StatusCode != HttpStatusCode.Redirect || r2.Headers.Location == null)
    {
        Err($"{name}:post:{(int)r2.StatusCode}:{Trunc(WebUtility.HtmlDecode(alertRe.Match(b2).Groups[1].Value))}");
        return false;
    }
    if (!jar.ContainsKey("ark_idp_sid")) { Err($"{name}:no_session_cookie"); return false; }
    if (!await Redeem(u, r2.Headers.Location.ToString(), verifier, name)) return false;
    Rec($"{name}.TOTAL", Stopwatch.GetElapsedTime(total).TotalMilliseconds);
    return true;
}

// The session ran out (or was ended): what a person does next is sign in again.
async Task SignInAgain(VUser u)
{
    Interlocked.Increment(ref expired);
    await SignIn(u, "resignin");
}

async Task Sso(VUser u)
{
    var total = Stopwatch.GetTimestamp();
    var (verifier, challenge) = Pkce();
    var (r, b) = await Send("sso.authorize", Req(HttpMethod.Get, AuthorizeUrl(challenge, B64Url(RandomNumberGenerator.GetBytes(12))), u.Cookies));
    if (IsSignInPage(r, b)) { await SignInAgain(u); return; }
    if (r.StatusCode != HttpStatusCode.Redirect || r.Headers.Location == null) { Err($"sso:authorize:{(int)r.StatusCode}"); return; }
    if (await Redeem(u, r.Headers.Location.ToString(), verifier, "sso"))
        Rec("sso.TOTAL", Stopwatch.GetElapsedTime(total).TotalMilliseconds);
}

async Task Refresh(VUser u)
{
    var token = u.RefreshToken;
    if (token == null) { Err("refresh:none"); return; }
    var form = new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = token, ["client_id"] = clientId };
    if (clientSecret != null) form["client_secret"] = clientSecret;
    var (resp, body) = await Send("refresh", new HttpRequestMessage(HttpMethod.Post, $"{issuer}/oauth2/token") { Content = new FormUrlEncodedContent(form) });
    // An ended session takes its refresh tokens with it: expected once sessions start running out.
    if (resp.StatusCode == HttpStatusCode.BadRequest && body.Contains("invalid_grant") && (body.Contains("session") || body.Contains("revoked") || body.Contains("is invalid")))
    {
        await SignInAgain(u);
        return;
    }
    if (resp.StatusCode != HttpStatusCode.OK) { Err($"refresh:{(int)resp.StatusCode}:{Trunc(body)}"); return; }
    TakeTokens(u, body);
}

async Task UserInfo(VUser u)
{
    var req = new HttpRequestMessage(HttpMethod.Get, $"{issuer}/oauth2/userinfo");
    req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {u.AccessToken}");
    var (resp, body) = await Send("userinfo", req);
    if (resp.StatusCode != HttpStatusCode.OK) { Err($"userinfo:{(int)resp.StatusCode}"); return; }
    if (!body.Contains(u.Email)) Err("userinfo:wrong_subject");
}

// RFC 9126: the client pushes the request, the browser carries only its handle.
async Task Par(VUser u)
{
    var total = Stopwatch.GetTimestamp();
    var (verifier, challenge) = Pkce();
    var state = B64Url(RandomNumberGenerator.GetBytes(12));
    var (p, pb) = await Send("par.push", new HttpRequestMessage(HttpMethod.Post, $"{issuer}/oauth2/par")
    {
        Content = Form(("client_id", clientId), ("client_secret", clientSecret!), ("response_type", "code"), ("redirect_uri", redirect),
            ("scope", "openid profile email offline_access"), ("state", state), ("nonce", state),
            ("code_challenge", challenge), ("code_challenge_method", "S256"))
    });
    if ((int)p.StatusCode is not (200 or 201)) { Err($"par:push:{(int)p.StatusCode}:{Trunc(pb)}"); return; }
    string requestUri;
    using (var doc = JsonDocument.Parse(pb)) requestUri = doc.RootElement.GetProperty("request_uri").GetString()!;

    var (r, b) = await Send("par.authorize", Req(HttpMethod.Get,
        $"{issuer}/oauth2/authorize?client_id={clientId}&request_uri={Uri.EscapeDataString(requestUri)}", u.Cookies));
    if (IsSignInPage(r, b)) { await SignInAgain(u); return; }
    if (r.StatusCode != HttpStatusCode.Redirect || r.Headers.Location == null) { Err($"par:authorize:{(int)r.StatusCode}"); return; }
    if (await Redeem(u, r.Headers.Location.ToString(), verifier, "par"))
        Rec("par.TOTAL", Stopwatch.GetElapsedTime(total).TotalMilliseconds);
}

// RFC 8628: a device asks for a code, the signed-in user approves it in the browser, the device collects its tokens.
async Task Device(VUser u)
{
    var total = Stopwatch.GetTimestamp();
    var (d, db) = await Send("device.start", new HttpRequestMessage(HttpMethod.Post, $"{issuer}/oauth2/device_authorization")
    {
        Content = Form(("client_id", "load_device"), ("scope", "openid profile"))
    });
    if (d.StatusCode != HttpStatusCode.OK) { Err($"device:start:{(int)d.StatusCode}:{Trunc(db)}"); return; }
    string deviceCode, userCode;
    using (var doc = JsonDocument.Parse(db))
    {
        deviceCode = doc.RootElement.GetProperty("device_code").GetString()!;
        userCode = doc.RootElement.GetProperty("user_code").GetString()!;
    }

    var page = $"{issuer}/oauth2/device";
    var (g, gb) = await Send("device.page", Req(HttpMethod.Get, $"{page}?user_code={Uri.EscapeDataString(userCode)}", u.Cookies));
    TakeCookies(g, u.Cookies);
    var m = tokenRe.Match(gb);
    if (g.StatusCode != HttpStatusCode.OK || !m.Success) { Err($"device:page:{(int)g.StatusCode}"); return; }

    var (a, ab) = await Send("device.approve", Req(HttpMethod.Post, page, u.Cookies, Form(
        ("user_code", userCode), ("ark_action", "approve"), ("__RequestVerificationToken", WebUtility.HtmlDecode(m.Groups[1].Value)))));
    // No live session: the page sends the browser to sign in first.
    if (a.StatusCode == HttpStatusCode.Redirect) { await SignInAgain(u); return; }
    if (a.StatusCode != HttpStatusCode.OK) { Err($"device:approve:{(int)a.StatusCode}"); return; }

    var (t, tb) = await Send("device.token", new HttpRequestMessage(HttpMethod.Post, $"{issuer}/oauth2/token")
    {
        Content = Form(("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), ("device_code", deviceCode), ("client_id", "load_device"))
    });
    if (t.StatusCode != HttpStatusCode.OK) { Err($"device:token:{(int)t.StatusCode}:{Trunc(tb)}"); return; }
    if (!tb.Contains("access_token")) { Err("device:no_token"); return; }
    Rec("device.TOTAL", Stopwatch.GetElapsedTime(total).TotalMilliseconds);
}

// Sign out at the provider (which tells the application over the back channel), then come back and sign in.
async Task Logout(VUser u)
{
    if (u.IdToken == null) { Err("logout:no_id_token"); return; }
    var (r, b) = await Send("logout", Req(HttpMethod.Get,
        $"{issuer}/oauth2/logout?id_token_hint={Uri.EscapeDataString(u.IdToken)}&post_logout_redirect_uri={Uri.EscapeDataString("http://127.0.0.1:9/out")}&state=bye", u.Cookies));
    // 302 back to the application; 200 when the session had already run out and there was nothing to end.
    if (r.StatusCode != HttpStatusCode.Redirect && r.StatusCode != HttpStatusCode.OK) { Err($"logout:{(int)r.StatusCode}"); return; }
    TakeCookies(r, u.Cookies);
    await SignIn(u, "resignin");
}

// The legacy /v1 flow some older applications still use: no single sign-on, credentials posted every time.
async Task V1(VUser u)
{
    var total = Stopwatch.GetTimestamp();
    var (verifier, challenge) = Pkce();
    var jar = new Dictionary<string, string>();
    var url = $"{baseUrl}/oauth/{tenant}/v1/connect/authorize?response_type=code&client_id={clientId}&redirect_uri={Uri.EscapeDataString(redirect)}" +
              $"&scope=openid&state=v1&code_challenge={challenge}&code_challenge_method=S256";
    var (g, gb) = await Send("v1.page", Req(HttpMethod.Get, url, jar));
    TakeCookies(g, jar);
    var m = tokenRe.Match(gb);
    if (g.StatusCode != HttpStatusCode.OK || !m.Success) { Err($"v1:page:{(int)g.StatusCode}"); return; }

    var (p, pb) = await Send("v1.post", Req(HttpMethod.Post, url, jar, Form(
        ("Username", u.Email), ("Password", password), ("__RequestVerificationToken", WebUtility.HtmlDecode(m.Groups[1].Value)))));
    if (p.StatusCode != HttpStatusCode.Redirect || p.Headers.Location == null) { Err($"v1:post:{(int)p.StatusCode}"); return; }
    var code = System.Web.HttpUtility.ParseQueryString(new Uri(p.Headers.Location.ToString()).Query)["code"];
    if (string.IsNullOrEmpty(code)) { Err("v1:no_code"); return; }

    var (t, tb) = await Send("v1.token", new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/oauth/{tenant}/v1/token")
    {
        Content = Form(("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect), ("client_id", clientId), ("code_verifier", verifier))
    });
    if (t.StatusCode != HttpStatusCode.OK || !tb.Contains("access_token")) { Err($"v1:token:{(int)t.StatusCode}:{Trunc(tb)}"); return; }
    Rec("v1.TOTAL", Stopwatch.GetElapsedTime(total).TotalMilliseconds);
}

Task Run(string op, VUser u) => op switch
{
    "sso" => Sso(u), "refresh" => Refresh(u), "userinfo" => UserInfo(u), "par" => Par(u),
    "device" => Device(u), "logout" => Logout(u), "v1" => V1(u),
    _ => throw new ArgumentException($"unknown operation '{op}' in --mix")
};
string Pick(Random rnd)
{
    var roll = rnd.Next(mixTotal);
    foreach (var (op, weight) in mix) { if (roll < weight) return op; roll -= weight; }
    return mix[^1].op;
}

// ---------------------------------------------------------------- back-channel logout receiver
HttpListener? listener = null;
if (bclPort > 0)
{
    listener = new HttpListener();
    listener.Prefixes.Add($"http://127.0.0.1:{bclPort}/");
    listener.Start();
    _ = Task.Run(async () =>
    {
        while (listener.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = await listener.GetContextAsync(); } catch { break; }
            _ = Task.Run(async () =>
            {
                try
                {
                    using var reader = new StreamReader(ctx.Request.InputStream);
                    var body = await reader.ReadToEndAsync();
                    if (body.StartsWith("logout_token=")) Interlocked.Increment(ref logoutTokens);
                    ctx.Response.StatusCode = 200;
                    ctx.Response.Close();
                }
                catch { }
            });
        }
    });
}

// ---------------------------------------------------------------- population
var vusers = Enumerable.Range(offset, users).Select(i => new VUser { Email = $"user{i:D5}@load.test" }).ToArray();
var pool = new VUser[users];
var poolCount = 0;
void Admit(VUser u) { lock (pool) pool[poolCount++] = u; }

Console.WriteLine($"[{label}] {baseUrl}{(instances.Length > 1 ? $" (+{instances.Length - 1})" : "")}  client={clientId}  users={users} (from {offset})  " +
                  (arrivalRate > 0 ? $"arriving {arrivalRate}/s" : $"concurrency={conc}") + $"  mix={mixSpec}");

var windows = new List<object>();
double Pct(double[] sorted, double p) => sorted.Length == 0 ? 0 : sorted[Math.Min(sorted.Length - 1, (int)(sorted.Length * p))];
var clock = Stopwatch.StartNew();
long lastOps = 0;
void CloseWindow()
{
    var snap = Interlocked.Exchange(ref window, new ConcurrentDictionary<string, ConcurrentBag<double>>());
    var errs = Interlocked.Exchange(ref windowErrors, 0);
    var ops = Interlocked.Read(ref operations);
    var lag = Interlocked.Exchange(ref lagMs, 0);
    var line = new Dictionary<string, object>
    {
        ["generatorLagMs"] = lag,
        ["t"] = Math.Round(clock.Elapsed.TotalSeconds), ["signedIn"] = poolCount, ["opsPerSecond"] = Math.Round((ops - lastOps) / (double)windowSeconds, 1),
        ["errors"] = errs, ["reSignIns"] = Interlocked.Read(ref expired), ["logoutTokens"] = Interlocked.Read(ref logoutTokens), ["shed"] = Interlocked.Read(ref shed)
    };
    lastOps = ops;
    var text = new StringBuilder($"  t={clock.Elapsed.TotalSeconds,5:0}s in={poolCount,6} ops/s={line["opsPerSecond"],6} err={errs,3} lag={lag,4}ms");
    foreach (var step in new[] { "signin.TOTAL", "refresh", "sso.TOTAL", "userinfo" })
    {
        if (!snap.TryGetValue(step, out var bag)) continue;
        var a = bag.ToArray(); Array.Sort(a);
        line[step] = new { count = a.Length, p50 = Pct(a, .50), p95 = Pct(a, .95), p99 = Pct(a, .99) };
        text.Append($"  {step.Replace(".TOTAL", "")} {Pct(a, .50):0.0}/{Pct(a, .95):0.0}");
    }
    windows.Add(line);
    Console.WriteLine(text + "   (p50/p95 ms)");
}

double signinSeconds, signinRate, steadyRps = 0;
long steadyOps = 0;

if (arrivalRate <= 0)
{
    // ------------------------------------------------------------ everyone signs in, then the steady mix
    var sw1 = Stopwatch.StartNew();
    var next = -1; var done = 0;
    await Task.WhenAll(Enumerable.Range(0, conc).Select(async _ =>
    {
        while (true)
        {
            var i = Interlocked.Increment(ref next);
            if (i >= vusers.Length) break;
            try { if (await SignIn(vusers[i])) Admit(vusers[i]); } catch (Exception ex) { Err($"signin:exception:{ex.GetType().Name}"); }
            var d = Interlocked.Increment(ref done);
            if (d % 2000 == 0) Console.WriteLine($"  .. {d} sign-ins, {sw1.Elapsed.TotalSeconds:0}s, {d / sw1.Elapsed.TotalSeconds:0.0}/s");
        }
    }));
    sw1.Stop();
    signinSeconds = sw1.Elapsed.TotalSeconds;
    signinRate = poolCount / signinSeconds;
    Console.WriteLine($"sign-in phase: {poolCount}/{users} ok in {signinSeconds:0.0}s = {signinRate:0.0} sign-ins/s");
}
else
{
    signinSeconds = users / arrivalRate;
    signinRate = arrivalRate;
}

if (steadySeconds > 0 && (poolCount > 0 || arrivalRate > 0))
{
    var before = stats.Sum(kv => kv.Key.EndsWith("TOTAL") ? 0 : kv.Value.Count);
    var sw2 = Stopwatch.StartNew();
    clock.Restart();
    var inFlight = 0;
    var tasks = new List<Task>();

    async Task One(Random rnd)
    {
        // each virtual user is driven by one operation at a time: a refresh token is single use
        VUser? u = null;
        for (var tries = 0; tries < 8 && u == null; tries++)
        {
            var n = Volatile.Read(ref poolCount);
            if (n == 0) return;
            var candidate = pool[rnd.Next(n)];
            if (await candidate.Gate.WaitAsync(0)) u = candidate;
        }
        if (u == null) return;
        try { await Run(Pick(rnd), u); Interlocked.Increment(ref operations); }
        catch (Exception ex) { Err($"steady:exception:{ex.GetType().Name}"); }
        finally { u.Gate.Release(); }
    }

    // people arriving, at a fixed rate whatever the provider is doing
    if (arrivalRate > 0)
    {
        tasks.Add(Task.Run(async () =>
        {
            var started = 0;
            while (started < vusers.Length && sw2.Elapsed.TotalSeconds < steadySeconds)
            {
                var due = (int)Math.Min(vusers.Length, sw2.Elapsed.TotalSeconds * arrivalRate);
                while (started < due)
                {
                    var u = vusers[started++];
                    _ = Task.Run(async () =>
                    {
                        await u.Gate.WaitAsync();
                        try { if (await SignIn(u)) Admit(u); }
                        catch (Exception ex) { Err($"signin:exception:{ex.GetType().Name}"); }
                        finally { u.Gate.Release(); }
                    });
                }
                await Task.Delay(10);
            }
        }));
    }

    if (rate > 0)
    {
        // open loop: the rate grows with the number of people signed in, and does not slow down when the provider does
        tasks.Add(Task.Run(async () =>
        {
            var rnd = new Random(7);
            double budget = 0; var last = sw2.Elapsed.TotalSeconds;
            while (sw2.Elapsed.TotalSeconds < steadySeconds)
            {
                var now = sw2.Elapsed.TotalSeconds;
                budget += (now - last) * rate * Volatile.Read(ref poolCount) / users;
                last = now;
                while (budget >= 1)
                {
                    budget -= 1;
                    if (Volatile.Read(ref inFlight) >= steadyConc) { Interlocked.Increment(ref shed); continue; }
                    Interlocked.Increment(ref inFlight);
                    var seed = rnd.Next();
                    _ = Task.Run(async () => { try { await One(new Random(seed)); } finally { Interlocked.Decrement(ref inFlight); } });
                }
                await Task.Delay(5);
            }
        }));
    }
    else
    {
        tasks.AddRange(Enumerable.Range(0, steadyConc).Select(w => Task.Run(async () =>
        {
            var rnd = new Random(1000 + w);
            while (sw2.Elapsed.TotalSeconds < steadySeconds)
            {
                if (Volatile.Read(ref poolCount) == 0) { await Task.Delay(50); continue; }
                await One(rnd);
            }
        })));
    }

    tasks.Add(Task.Run(async () =>
    {
        while (sw2.Elapsed.TotalSeconds < steadySeconds)
        {
            await Task.Delay(TimeSpan.FromSeconds(windowSeconds));
            CloseWindow();
        }
    }));

    await Task.WhenAll(tasks);
    // let what is in flight finish
    for (var i = 0; i < 300 && (Volatile.Read(ref inFlight) > 0 || vusers.Any(v => v.Gate.CurrentCount == 0)); i++) await Task.Delay(100);
    sw2.Stop();
    steadyOps = Interlocked.Read(ref operations);
    var requests = stats.Sum(kv => kv.Key.EndsWith("TOTAL") ? 0 : kv.Value.Count) - before;
    steadyRps = requests / sw2.Elapsed.TotalSeconds;
    Console.WriteLine($"steady phase: {steadyOps} operations, {requests} requests in {sw2.Elapsed.TotalSeconds:0.0}s = {steadyRps:0.0} req/s, {poolCount}/{users} signed in" +
                      $", {expired} sign-ins after a session ended, {logoutTokens} logout tokens received, {shed} operations shed");
}
listener?.Stop();

Console.WriteLine($"{"step",-18}{"count",9}{"p50",9}{"p95",9}{"p99",9}{"max",9}   (ms)");
var summary = new Dictionary<string, object>();
foreach (var kv in stats.OrderBy(k => k.Key))
{
    var a = kv.Value.ToArray(); Array.Sort(a);
    Console.WriteLine($"{kv.Key,-18}{a.Length,9}{Pct(a, .50),9:0.0}{Pct(a, .95),9:0.0}{Pct(a, .99),9:0.0}{a[^1],9:0.0}");
    summary[kv.Key] = new { count = a.Length, p50 = Pct(a, .50), p95 = Pct(a, .95), p99 = Pct(a, .99), max = a[^1] };
}
var errTotal = errors.Values.Sum();
Console.WriteLine($"errors: {errTotal}");
foreach (var e in errors.OrderByDescending(e => e.Value).Take(12)) Console.WriteLine($"  {e.Value,7}  {e.Key}");
if (outFile.Length > 0)
    File.WriteAllText(outFile, JsonSerializer.Serialize(new
    {
        label, users, conc, steadyConc, signedIn = poolCount, signinSeconds, signinRate, steadyRps, steadyOps, mix = mixSpec,
        reSignIns = expired, logoutTokens, shed, errors = errTotal, errorKinds = errors, steps = summary, windows
    }, new JsonSerializerOptions { WriteIndented = true }));
return errTotal == 0 ? 0 : 1;

class VUser
{
    public string Email = "";
    public Dictionary<string, string> Cookies = new();
    public string? AccessToken, RefreshToken, IdToken;
    public SemaphoreSlim Gate = new(1, 1);
}
