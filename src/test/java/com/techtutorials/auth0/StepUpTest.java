package com.techtutorials.auth0;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class StepUpTest {

    @Autowired
    MockMvc mvc;

    @Test
    void anonymousUserIsSentToLogin() throws Exception {
        mvc.perform(get("/account/security"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("http://localhost/oauth2/authorization/auth0"));
    }

    @Test
    void userWithoutMfaIsSentToStepUp() throws Exception {
        mvc.perform(get("/account/security").with(oidcLogin().idToken(t -> t.claim("amr", List.of("pwd")))))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/oauth2/authorization/auth0?step_up=true"))
            .andExpect(request().sessionAttribute("SPRING_SECURITY_SAVED_REQUEST", Matchers.notNullValue()));
    }

    @Test
    void userWithRecentMfaGetsIn() throws Exception {
        mvc.perform(get("/account/security").with(oidcLogin().idToken(t -> t
                .claim("amr", List.of("pwd", "mfa"))
                .issuedAt(Instant.now().minusSeconds(60)))))
            .andExpect(status().isOk());
    }

    @Test
    void staleMfaRequiresStepUpAgain() throws Exception {
        mvc.perform(get("/account/security").with(oidcLogin().idToken(t -> t
                .claim("amr", List.of("mfa"))
                .issuedAt(Instant.now().minusSeconds(3600)))))
            .andExpect(redirectedUrl("/oauth2/authorization/auth0?step_up=true"));
    }

    @Test
    void ordinaryPagesDoNotNeedMfa() throws Exception {
        mvc.perform(get("/profile").with(oidcLogin().idToken(t -> t.claim("email", "a@b.c").claim("name", "A"))))
            .andExpect(status().isOk());
    }

    @Test
    void missingRoleIsA403NotAStepUp() throws Exception {
        mvc.perform(get("/admin/x").with(oidcLogin().idToken(t -> t.claim("amr", List.of("pwd")))))
            .andExpect(status().isForbidden());
    }

    @Test
    void stepUpLoginAddsAcrValues() throws Exception {
        mvc.perform(get("/oauth2/authorization/auth0").param("step_up", "true"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", allOf(
                containsString("https://tenant.example.auth0.com/authorize"),
                containsString("acr_values=http://schemas.openid.net/pape/policies/2007/06/multi-factor"))));
    }

    @Test
    void normalLoginHasNoAcrValues() throws Exception {
        mvc.perform(get("/oauth2/authorization/auth0"))
            .andExpect(header().string("Location", Matchers.not(containsString("acr_values"))));
    }
}
