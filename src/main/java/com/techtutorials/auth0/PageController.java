package com.techtutorials.auth0;

import java.time.Instant;
import java.util.List;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class PageController {

    private final StepUpAuthorizationManager stepUp;

    public PageController(StepUpAuthorizationManager stepUp) {
        this.stepUp = stepUp;
    }

    @GetMapping("/")
    public String home() {
        return "index";
    }

    /** Any signed-in user: shows the ID token claims that drive step-up decisions. */
    @GetMapping("/profile")
    public String profile(@AuthenticationPrincipal OidcUser user, Model model) {
        List<String> amr = user.getIdToken().getClaimAsStringList("amr");
        List<String> roles = user.getIdToken().getClaimAsStringList(SecurityConfig.ROLES_CLAIM);
        Instant issuedAt = user.getIdToken().getIssuedAt();
        model.addAttribute("user", user);
        model.addAttribute("amr", amr == null ? List.of() : amr);
        model.addAttribute("roles", roles == null ? List.of() : roles);
        model.addAttribute("issuedAt", issuedAt);
        model.addAttribute("claims", user.getIdToken().getClaims());
        return "profile";
    }

    /** Step-up protected: only reachable with a recent MFA challenge. */
    @GetMapping("/account/security")
    public String security(@AuthenticationPrincipal OidcUser user, Model model) {
        model.addAttribute("user", user);
        model.addAttribute("issuedAt", user.getIdToken().getIssuedAt());
        return "security";
    }

    /** Also step-up protected; a stale session gets a 403 instead of slipping through. */
    @PostMapping("/account/security/recovery-email")
    public String updateRecoveryEmail(@RequestParam String recoveryEmail, RedirectAttributes redirect) {
        // A real app would persist this against user.getSubject()
        redirect.addFlashAttribute("message", "Recovery email changed to " + recoveryEmail);
        return "redirect:/account/security";
    }

    @GetMapping("/payments")
    public String payments() {
        return "payments";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }
}
