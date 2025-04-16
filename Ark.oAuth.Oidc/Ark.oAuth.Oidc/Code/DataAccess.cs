using Microsoft.EntityFrameworkCore;
using MySqlX.XDevAPI;

namespace Ark.oAuth.Oidc
{
    public class DataAccess
    {
        ArkDataContext _ctx;
        ArkUtil _util;
        public DataAccess(ArkDataContext ctx, ArkUtil util)
        {
            _ctx = ctx;
            _util = util;
        }
        public async Task<ArkTenant?> GetTenant(string tenant_id)
        {
            return await _ctx.tenants.FirstOrDefaultAsync(t => t.tenant_id.ToLower().Trim() == (tenant_id ?? "").ToLower().Trim());
        }
        public async Task<List<ArkTenant>> GetTenants()
        {
            return await _ctx.tenants.ToListAsync();
        }
        public async Task<ArkClient?> GetClient(string client_id)
        {
            return await _ctx.clients.FirstOrDefaultAsync(t => t.client_id.ToLower().Trim() == (client_id ?? "").ToLower().Trim());
        }
        public async Task<ArkTenant> UpsertTenant(ArkTenant tenant)
        {
            var tt = await _ctx.tenants.FirstOrDefaultAsync(t => t.tenant_id == tenant.tenant_id);
            if (tt == null)
            {
                tenant.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.tenants.Add(tenant);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                tenant.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.tenants.Update(tenant);
            }
            await _ctx.SaveChangesAsync();
            return tenant;
        }
        public async Task<List<ArkClient>> GetClients()
        {
            return await _ctx.clients.ToListAsync();
        }
        public async Task<ArkClient> UpsertClient(ArkClient client)
        {
            var tt = await _ctx.clients.FirstOrDefaultAsync(t => t.client_id == client.client_id);
            if (tt == null)
            {
                client.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.clients.Add(client);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                client.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.clients.Update(client);
            }
            await _ctx.SaveChangesAsync();
            return client;
        }
        public async Task<List<ArkClaim>> GetClaims()
        {
            return await _ctx.claims.ToListAsync();
        }
        public async Task<ArkClaim> UpsertClaim(ArkClaim claim)
        {
            var tt = await _ctx.claims.FirstOrDefaultAsync(t => t.key == claim.key);
            if (tt == null)
            {
                _ctx.claims.Add(claim);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                _ctx.claims.Update(claim);
            }
            await _ctx.SaveChangesAsync();
            return claim;
        }
        public async Task<List<ArkUser>> GetUsers()
        {
            return await _ctx.users.ToListAsync();
        }
        public async Task<ArkUser> UpsertUser(ArkUser user)
        {
            var tt = await _ctx.users.FirstOrDefaultAsync(t => t.email == user.email);
            if (tt == null)
            {
                // new user - ste reset mode - true
                user.reset_mode = true;
                user.ref_uid = Guid.NewGuid().ToString();
                string email_content = System.IO.File.ReadAllText(System.IO.Path.Combine(Environment.CurrentDirectory, "wwwroot", "email", "user_activation_.html"));
                await _util.SendMail(user.email, email_content, "NTTDATA: Intelligent Scheduler - Activation Link");
                user.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.users.Add(user);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                user.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.users.Update(user);
            }
            await _ctx.SaveChangesAsync();
            return user;
        }
        public async Task<PkceCodeFlow?> GetPkceCode(string code)
        {
            return await _ctx.pkce_code_flow.FirstOrDefaultAsync(t => t.code == code);
        }
        public async Task UpsertPkceCode(string token, ArkTenant tenant, string code, string code_challenge, string code_challenge_method, string state, string scopes, string claims, DateTime expires_at, string redirect_uri, string response_type)
        {
            _ctx.pkce_code_flow.Add(new PkceCodeFlow()
            {
                access_token = token,
                audience = tenant.audience,
                client_id = tenant.tenant_id,
                code = code,
                code_challenge = code_challenge,
                code_challenge_method = code_challenge_method,
                state = state,
                refresh_token = code_challenge,
                scopes = scopes,
                claims = claims,
                expires_at = expires_at,
                created_at = DateTime.UtcNow,
                redirect_uri = redirect_uri,
                response_type = response_type
            });
            await _ctx.SaveChangesAsync();
        }
        public async Task ExecuteRaw(string sql)
        {
            _ctx.Database.ExecuteSqlRaw(sql);
        }
        public async Task EnsureCreatedAsync()
        {
            await _ctx.Database.EnsureCreatedAsync();
        }
    }
}
