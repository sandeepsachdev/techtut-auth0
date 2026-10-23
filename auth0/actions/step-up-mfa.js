/**
 * Auth0 Action - trigger: Login / Post Login
 *
 * Requires MFA whenever the application asks for it with
 *   acr_values=http://schemas.openid.net/pape/policies/2007/06/multi-factor
 * (see StepUpAuthorizationRequestResolver). Set the tenant's
 * "Require Multi-factor Auth" policy to "Never" so this Action decides.
 */
const MFA_POLICY = 'http://schemas.openid.net/pape/policies/2007/06/multi-factor';

exports.onExecutePostLogin = async (event, api) => {
  const requested = event.transaction?.acr_values ?? [];

  if (requested.includes(MFA_POLICY)) {
    // Always challenge on step-up; don't let a remembered browser skip it
    api.multifactor.enable('any', { allowRememberBrowser: false });
  }
};
