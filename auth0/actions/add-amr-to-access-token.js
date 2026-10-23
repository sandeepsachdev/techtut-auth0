/**
 * Auth0 Action - trigger: Login / Post Login
 *
 * Access tokens don't include "amr" by default. This copies the completed
 * authentication methods into a namespaced claim so the API can require MFA
 * (see ApiSecurityConfig.AMR_CLAIM).
 */
exports.onExecutePostLogin = async (event, api) => {
  const methods = (event.authentication?.methods ?? []).map((m) => m.name);
  api.accessToken.setCustomClaim('https://example.com/amr', methods);
};
