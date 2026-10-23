package com.techtutorials.auth0;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

/**
 * Grants access only if the user's ID token shows that MFA was performed
 * ({@code amr} contains {@code "mfa"}) and the token was issued recently.
 */
@Component
public class StepUpAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final Duration maxAge;

    public StepUpAuthorizationManager(@Value("${app.step-up.max-age:10m}") Duration maxAge) {
        this.maxAge = maxAge;
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        return new AuthorizationDecision(isSteppedUp(authentication.get()));
    }

    public boolean isSteppedUp(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof OidcUser user)) {
            return false;
        }
        List<String> amr = user.getIdToken().getClaimAsStringList("amr");
        Instant issuedAt = user.getIdToken().getIssuedAt();
        return amr != null && amr.contains("mfa")
            && issuedAt != null
            && issuedAt.isAfter(Instant.now().minus(maxAge));
    }
}
