using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
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
        public async Task<ArkClient?> GetClient(string tenant_id, string client_id) //cmposite key
        {
            return await _ctx.clients.FirstOrDefaultAsync(t => t.tenant_id.ToLower().Trim() == (tenant_id ?? "").ToLower().Trim() &&  t.client_id.ToLower().Trim() == (client_id ?? "").ToLower().Trim());
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
            if (string.IsNullOrEmpty((client?.id ?? "").Trim())) client.id = null;
            var tt = (await _ctx.clients.FirstOrDefaultAsync(t => t.id.ToLower() == (client.id ?? "").ToLower())) ?? (await _ctx.clients.FirstOrDefaultAsync(t => t.tenant_id.ToLower() == (client.tenant_id ?? "").ToLower() && t.client_id.ToLower() == (client.client_id ?? "").ToLower()));
            if (tt == null)
            {
                client.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.clients.Add(client);
            }
            else
            {
                client.id = tt.id;
                _ctx.ChangeTracker.Clear();
                client.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.clients.Update(client);
            }
            await _ctx.SaveChangesAsync();
            return client;
        }
        public async Task<ArkClient> DeleteClient(ArkClient client)
        {
            if (string.IsNullOrEmpty(client.id)) return client; //added on the UI, delete before even saving
            var tt = await _ctx.clients.FirstOrDefaultAsync(t => t.id.ToLower() == client.id.ToLower());
            if (tt == null)
            {
                
            }
            else
            {
                _ctx.clients.Remove(tt);
            }
            await _ctx.SaveChangesAsync();
            return client;
        }
        public async Task<List<ArkClaim>> GetClaims()
        {
            return await _ctx.claims.ToListAsync();
        }
        public async Task<ArkClaim?> GetClaim(string key)
        {
            return await _ctx.claims.FirstOrDefaultAsync(t => t.key.ToLower().Trim() == key.ToLower().Trim());
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
        public async Task<List<ArkUserClientClaim>> GetUsersClientClaims(string email, string tenatn_id)
        {
            return await _ctx.user_client_claims.Where(t1 =>
                    (email ?? "").ToLower() == (t1.email ?? "").ToLower() && (tenatn_id ?? "").ToLower() == (t1.tenant_id ?? "").ToLower()).ToListAsync();
        }
        public async Task<ArkUserClientClaim> UpsertUsersClientClaims(ArkUserClientClaim us_cl)
        {
            if (string.IsNullOrEmpty((us_cl?.id ?? "").Trim())) us_cl.id = null;
            var tt = (await _ctx.user_client_claims.FirstOrDefaultAsync(t => (t.id ?? "").ToLower().Trim() == (us_cl.id ?? "").ToLower().Trim())) 
                ?? (await _ctx.user_client_claims.FirstOrDefaultAsync(t => 
                                (t.tenant_id ?? "").ToLower().Trim() == (us_cl.tenant_id ?? "").ToLower().Trim() 
                            &&  (t.client_id ?? "").ToLower().Trim() == (us_cl.client_id ?? "").ToLower().Trim() 
                            &&  (t.email ?? "").ToLower().Trim() == (us_cl.email ?? "").ToLower().Trim()));
            if (tt == null)
            {
                us_cl.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.user_client_claims.Add(us_cl);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                us_cl.id = tt.id;
                us_cl.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.user_client_claims.Update(us_cl);
            }
            await _ctx.SaveChangesAsync();
            return us_cl;
        }
        public async Task<ArkUserClientClaim> DeleteUsersClientClaims(ArkUserClientClaim us_cl)
        {
            if (string.IsNullOrEmpty(us_cl?.id)) return us_cl; //added on the UI, delete before even saving
            var tt = await _ctx.user_client_claims.FirstOrDefaultAsync(t => t.id.ToLower() == us_cl.id.ToLower());
            if (tt == null)
            {

            }
            else
            {
                _ctx.user_client_claims.Remove(tt);
            }
            await _ctx.SaveChangesAsync();
            return us_cl;
        }
        public async Task<ArkUser> UpsertUser(ArkUser user)
        {
            if (string.IsNullOrEmpty(user?.email)) throw new ApplicationException("empty email");
            user.email = user.email.ToLower().Trim();
            if (!ark.net.util.EmailUtil.IsValidFormat(user.email)) throw new ApplicationException("invalid email format");
            var tt = await _ctx.users.FirstOrDefaultAsync(t => t.email == user.email);
            if (tt == null)
            {
                var usr_cl = await _ctx.user_client_claims.FirstOrDefaultAsync(t => t.email.ToLower() == user.email.ToLower());
                user.hash_pw = string.IsNullOrEmpty(user.hash_pw) ? _util.HashPasswordPBKDF2(_util.ServerConfig.DefaultPw) : user.hash_pw; //default pw
                user.reset_mode = true;
                user.ref_uid = Guid.NewGuid().ToString();
                string email_content = await _util.GetActivationEmail( _util.ServerConfig.TenantId, user.ref_uid);
                user.emailed = await _util.SendMail(user.email, email_content, $"{_util.ServerConfig.EmailConfig?.subject} Activation Link", this);
                user.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.users.Add(user);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                user.id = tt.id;
                user.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.users.Update(user);
            }
            await _ctx.SaveChangesAsync();
            return user;
        }
        public async Task<ArkUser> UserResetPw(ArkUser user)
        {
            var uu = await _ctx.users.FirstOrDefaultAsync(t => t.email == user.email);
            if (uu == null)
            {
                // Shouldn't be the case
            }
            else
            {
                var tnt = await _ctx.tenants.FirstOrDefaultAsync();
                _ctx.ChangeTracker.Clear();
                uu.reset_mode = true;
                uu.ref_uid = Guid.NewGuid().ToString();
                string email_content = await _util.GetActivationEmail(tnt.tenant_id, uu.ref_uid);
                uu.emailed = await _util.SendMail(uu.email, email_content, $"{_util.ServerConfig.EmailConfig?.subject} Reset Password", this);
                uu.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.users.Update(uu);
            }
            await _ctx.SaveChangesAsync();
            return uu;
        }
        public async Task<bool> UpdatePassword(string uq_refid, string pw)
        {
            var uu = await _ctx.users.FirstOrDefaultAsync(t => t.ref_uid == uq_refid);
            if (uu == null) throw new ApplicationException("invalid reference id, pls contact support.");
            else if (uu.reset_mode.HasValue && uu.reset_mode.Value)
            {
                _ctx.ChangeTracker.Clear();
                uu.reset_mode = false;
                uu.hash_pw = _util.HashPasswordPBKDF2(pw);
                uu.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.users.Update(uu);
                await _ctx.SaveChangesAsync();
            }
            else throw new ApplicationException("reset request expired, pls contact support.");
            return true;
        }
        public async Task<ArkUser> ValidateUserCreds(string un, string pw, string client, string tenant_id)
        {
            var usr = _ctx.users.FirstOrDefault(t => t.email.ToLower() == un.ToLower());
            if (usr == null) throw new ApplicationException("invalid creds");
            var clnt = _ctx.clients.FirstOrDefault(t => (t.client_id ?? "").ToLower() == (client ?? "").ToLower() && (t.tenant_id ?? "").ToLower() == (tenant_id ?? "").ToLower());
            if (clnt == null) throw new ApplicationException("invalid creds client");
            var usr_cl_cl = _ctx.user_client_claims.FirstOrDefault(t => t.email == un && (t.client_id ?? "").ToLower() == (clnt.id ?? "").ToLower() && (t.tenant_id ?? "").ToLower() == (tenant_id ?? "").ToLower());
            if (usr_cl_cl == null) throw new ApplicationException("invalid creds client.");
            if (!_util.VerifyPasswordPBKDF2(pw, usr.hash_pw)) throw new ApplicationException("invalid creds.");
            return usr;
        }
        public async Task<PkceCodeFlow?> GetPkceCode(string code, bool invalidate = false)
        {
            var tt = await _ctx.pkce_code_flow.FirstOrDefaultAsync(t => t.code == code && !t.inactivate);
            if (invalidate)
            {
                tt.inactivate = true;
                _ctx.pkce_code_flow.Update(tt);
                await _ctx.SaveChangesAsync();
            }
            return tt;
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
                refresh_token = Guid.NewGuid().ToString(),
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
        public void Log(string? ref_key, string? ref_val, string? message, string? details, string? log_type = "trace")
        {
            try
            {
                if (!_util.IsTraceEnabled) return;
                _ctx.audit_trace.Add(new ArkAudit()
                {
                    ref_key = ref_key,
                    ref_val = ref_val,
                    log_type = log_type,
                    message = message,
                    details = details,
                    by = "ark_admin",
                    ip = "",
                    at = DateTime.UtcNow
                });
                _ctx.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
        public void LogError(Exception exp, string? ref_key, string? ref_val, string? message)
        {
            try
            {
                _ctx.audit_trace.Add(new ArkAudit()
                {
                    ref_key = ref_key,
                    ref_val = ref_val,
                    log_type = "error",
                    message = message,
                    details = exp.ToString(),
                    by = "ark_admin",
                    ip = "",
                    at = DateTime.UtcNow
                });
                _ctx.ChangeTracker.Clear();
                _ctx.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
    }
}
