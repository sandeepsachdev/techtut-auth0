/**
 * Auth0 Action - trigger: Login / Post Login
 *
 * Adds the user's Auth0 RBAC roles to the ID token and access token so the
 * Spring Boot app can map them to ROLE_* authorities (see SecurityConfig.ROLES_CLAIM).
 */
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://example.com';
  const roles = event.authorization?.roles ?? [];
  api.idToken.setCustomClaim(`${namespace}/roles`, roles);
  api.accessToken.setCustomClaim(`${namespace}/roles`, roles);
};
