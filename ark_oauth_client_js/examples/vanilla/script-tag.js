// The same client from a plain <script> tag: window.ArkOAuth is the whole package.
(async function () {
  const config = await (await fetch('/config.json')).json();
  const ark = new ArkOAuth.ArkBrowserClient({
    authority: config.authority,
    clientId: config.clientId
  });
  window.ark = ark;

  ark.subscribe(function (state) {
    document.getElementById('status').textContent = state.isAuthenticated ? 'Signed in as ' + state.user.email : state.status;
  });
  document.getElementById('signin').onclick = function () {
    ark.signinRedirect();
  };
  document.getElementById('signout').onclick = function () {
    ark.signoutRedirect();
  };
  await ark.init();
})();
