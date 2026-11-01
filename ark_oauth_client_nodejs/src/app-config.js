/**
 * The `ark_oauth_client` configuration section, as the .NET client binds it.
 *
 * An Ark application usually already has this section in an `appsettings.json`. Rather than have a
 * Node service restate it in its own spelling, `ArkAuthConfig.fromMapping` reads it as-is — C#
 * (`ClientId`), camel (`clientId`) or snake (`client_id`) — and returns the options `arkExpress()`
 * and `ArkOAuthClient` take.
 *
 * The legacy keys (`Issuer`, `RsaPublic`, `Tenants`, `RedirectUri`, …) are accepted and ignored.
 * They describe the v1 flow, whose callback route and pasted public key are exactly what discovery
 * replaced; carrying `RedirectUri` across would send users to the v1 callback. The redirect URI is
 * derived per request from `CallbackPath`, as the .NET handler does.
 */

/** Section key, folded (lower case, no underscores) → option name. */
const KEYS = new Map([
  ['authority', 'authority'],
  ['authserverurl', 'authServerUrl'],
  ['tenantid', 'tenantId'],
  ['clientid', 'clientId'],
  ['clientsecret', 'clientSecret'],
  ['scopes', 'scopes'],
  ['postlogoutredirecturi', 'postLogoutRedirectUri'],
  ['callbackpath', 'callbackPath'],
  ['loginpath', 'loginPath'],
  ['logoutpath', 'logoutPath'],
  ['autherrorpath', 'errorPath'],
  ['cookiename', 'cookieName'],
  ['roleclaimtype', 'roleClaim'],
  ['requirehttpsmetadata', 'requireHttps'],
  ['expiremins', 'sessionTtlSeconds'],
  ['accountswitch', 'accountSwitch']
]);

const fold = (key) => String(key).replace(/_/g, '').toLowerCase();
const camel = (key) => {
  const s = String(key);
  return s.includes('_') ? s.toLowerCase().replace(/_([a-z])/g, (_, c) => c.toUpperCase()) : s.charAt(0).toLowerCase() + s.slice(1);
};
const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

export const ArkAuthConfig = Object.freeze({
  /**
   * Binds the section. `{ ark_oauth_client: {...} }` and the inner object are both accepted, so a
   * whole parsed `appsettings.json` can be handed over.
   *
   * @param {Record<string, any>} data
   * @returns {Record<string, any>} options for arkExpress() / new ArkOAuthClient()
   */
  fromMapping(data) {
    let section = isPlainObject(data) ? data : {};
    const nested = Object.entries(section).find(([key, value]) => fold(key) === 'arkoauthclient' && isPlainObject(value));
    if (nested) section = nested[1];

    const options = {};
    for (const [key, value] of Object.entries(section)) {
      const name = KEYS.get(fold(key));
      if (!name || value === undefined || value === null || value === '') continue;

      if (name === 'accountSwitch') {
        if (isPlainObject(value)) options.accountSwitch = Object.fromEntries(Object.entries(value).map(([k, v]) => [camel(k), v]));
      } else if (name === 'sessionTtlSeconds') {
        const minutes = Number(value);
        if (Number.isFinite(minutes) && minutes > 0) options.sessionTtlSeconds = Math.max(60, Math.round(minutes * 60));
      } else if (name === 'scopes') {
        options.scopes = Array.isArray(value) ? value.map(String) : String(value).split(/[\s,]+/).filter(Boolean);
      } else {
        options[name] = value;
      }
    }
    return options;
  }
});
