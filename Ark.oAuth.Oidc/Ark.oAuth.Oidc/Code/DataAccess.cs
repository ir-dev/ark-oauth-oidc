using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc
{
    public class DataAccess
    {
        ArkDataContext _ctx;
        public DataAccess(ArkDataContext ctx)
        {
            _ctx = ctx;
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
        public async Task<List<ArkClient>> GetClients()
        {
            return await _ctx.clients.ToListAsync();
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
