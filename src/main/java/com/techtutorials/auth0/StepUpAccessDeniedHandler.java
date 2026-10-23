package com.techtutorials.auth0;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * When a logged-in user hits a step-up protected page without recent MFA,
 * remember the page and send them back to Auth0 with step-up requested.
 */
public class StepUpAccessDeniedHandler implements AccessDeniedHandler {

    private final StepUpAuthorizationManager stepUp;
    private final RequestMatcher stepUpPaths;
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final AccessDeniedHandler fallback = new AccessDeniedHandlerImpl();

    public StepUpAccessDeniedHandler(StepUpAuthorizationManager stepUp, RequestMatcher stepUpPaths) {
        this.stepUp = stepUp;
        this.stepUpPaths = stepUpPaths;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException ex) throws IOException, ServletException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean needsStepUp = stepUpPaths.matches(request)
            && auth != null && auth.getPrincipal() instanceof OidcUser
            && !stepUp.isSteppedUp(auth);
        if (needsStepUp && "GET".equals(request.getMethod())) {
            requestCache.saveRequest(request, response);
            response.sendRedirect(request.getContextPath() + StepUp.LOGIN_PATH + "?" + StepUp.STEP_UP_PARAM + "=true");
            return;
        }
        fallback.handle(request, response, ex);
    }
}
