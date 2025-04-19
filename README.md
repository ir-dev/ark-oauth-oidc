
TODO: update the md file

# ASP.NET Core IdentityServer - Authorization Code & Client Credentials Flow

This project is an implementation of oAuth2 oidc's **Authorization Code Flow with PKCE** and **Client Credentials Flow** using an ASP.NET Core application.

Customized in such a way that, its very felixible for develpers to to just start uinsg wiht out any hurdles.

Very much useful for SAAS based oauth enablement. considered most scenarios for tenant & client approach.

TO DO: soon to update a video file explaining this identity enablement with very few steps.

---

## 🔧 Prerequisites

- [.NET8 SDK](https://dotnet.microsoft.com/download)
- Basic knowledge of OAuth2 and OpenID Connect

---

## 📌 Authorization Code Flow with PKCE

### 🔹 When to Use

Use this flow for applications that require user authentication (like web apps or mobile apps).

### 🔹 Flow Steps

1. Client app redirects user to IdentityServer's `/authorize` endpoint.
2. User authenticates and consents.
3. IdentityServer returns an **authorization code**.
4. Client app sends code to `/token` endpoint with `code_verifier`.
5. IdentityServer validates and returns **access token** (and optionally **ID token**).

### 🔹 IdentityServer Configuration (in `Config.cs`)

```csharp
new Client
{
    ClientId = "web_client",
    ClientName = "Web Client",
    AllowedGrantTypes = GrantTypes.Code,
    RequirePkce = true,
    RequireClientSecret = false,
    RedirectUris = { "https://localhost:5002/signin-oidc" },
    PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },
    AllowedScopes = { "openid", "profile", "api1" },
    AllowAccessTokensViaBrowser = true
}
```

---

## 📌 Client Credentials Flow

### 🔹 When to Use

Use this flow for **machine-to-machine (M2M)** communication where no user is involved.

### 🔹 Flow Steps

1. The client authenticates directly with IdentityServer using its `client_id` and `client_secret`.
2. The client receives an **access token** to access protected APIs.

### 🔹 IdentityServer Configuration (in `Config.cs`)

```csharp
new Client
{
    ClientId = "m2m_client",
    ClientName = "Machine to Machine Client",
    AllowedGrantTypes = GrantTypes.ClientCredentials,
    ClientSecrets = { new Secret("super_secret".Sha256()) },
    AllowedScopes = { "api1" }
}
```

---

## 🧪 Sample API Resource Configuration

```csharp
new ApiScope("api1", "My API")
```

---

## 🧑‍💻 Sample Token Request (Client Credentials)

```bash
curl -X POST https://localhost:5001/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=m2m_client" \
  -d "client_secret=super_secret" \
  -d "grant_type=client_credentials" \
  -d "scope=api1"
```

---

## 🔐 Sample Token Request (Authorization Code - PKCE)

Frontend app initiates login:

```js
const url = "https://localhost:5001/connect/authorize?client_id=web_client&redirect_uri=https://localhost:5002/signin-oidc&response_type=code&scope=openid profile api1&code_challenge=xyz123&code_challenge_method=S256";
window.location.href = url;
```

Backend (after redirect):

```csharp
var tokenResponse = await httpClient.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
{
    Address = "https://localhost:5001/connect/token",
    ClientId = "web_client",
    Code = receivedCode,
    RedirectUri = "https://localhost:5002/signin-oidc",
    CodeVerifier = "original_code_verifier"
});
```

---

## 🛡️ Security Best Practices

- Use HTTPS everywhere.
- Keep client secrets secure.
- Use short-lived access tokens and refresh tokens if needed.
- Validate tokens on the API side using middleware.

---

## 📚 References

- [IdentityServer4 Documentation](https://identityserver4.readthedocs.io/)
- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

---

## 📁 Project Structure

```
/IdentityServerDemo
  /Config
    - Clients.cs
    - ApiScopes.cs
  /Controllers
  /wwwroot
  Program.cs
  Startup.cs
```

---

## 🚀 Run the Project

```bash
dotnet run --project IdentityServerDemo
```

Visit: `https://localhost:5001`

---
