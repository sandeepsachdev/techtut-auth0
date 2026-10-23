package com.techtutorials.auth0;

public final class StepUp {

    /** The OpenID PAPE policy URI Auth0 uses to signal "multi-factor authentication requested". */
    public static final String MFA_ACR =
        "http://schemas.openid.net/pape/policies/2007/06/multi-factor";

    /** Query parameter that tells our resolver to request step-up. */
    public static final String STEP_UP_PARAM = "step_up";

    public static final String LOGIN_PATH = "/oauth2/authorization/auth0";

    private StepUp() {
    }
}
