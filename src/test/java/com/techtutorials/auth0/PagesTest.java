package com.techtutorials.auth0;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class PagesTest {

    @Autowired
    MockMvc mvc;

    @Test
    void homeIsPublicAndOffersLogin() throws Exception {
        mvc.perform(get("/"))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("/oauth2/authorization/auth0")));
    }

    @Test
    void profileShowsClaims() throws Exception {
        mvc.perform(get("/profile").with(oidcLogin().idToken(t -> t
                .claim("email", "jane@example.com")
                .claim("amr", List.of("pwd"))
                .claim(SecurityConfig.ROLES_CLAIM, List.of("editor")))))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("jane@example.com")))
            .andExpect(content().string(containsString("editor")));
    }

    @Test
    void stepUpPageRendersAfterMfa() throws Exception {
        mvc.perform(get("/account/security").with(oidcLogin().idToken(t -> t
                .claim("email", "jane@example.com")
                .claim("amr", List.of("mfa"))
                .issuedAt(Instant.now()))))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Multi-factor authentication verified")));
    }

    @Test
    void paymentsRendersAfterMfa() throws Exception {
        mvc.perform(get("/payments").with(oidcLogin().idToken(t -> t.claim("amr", List.of("mfa")).issuedAt(Instant.now()))))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("manage payments")));
    }

    @Test
    void stepUpPostWithoutMfaIsForbidden() throws Exception {
        mvc.perform(post("/account/security/recovery-email").param("recoveryEmail", "x@example.com").with(csrf())
                .with(oidcLogin().idToken(t -> t.claim("amr", List.of("pwd")))))
            .andExpect(status().isForbidden());
    }

    @Test
    void stepUpPostWithMfaSucceeds() throws Exception {
        mvc.perform(post("/account/security/recovery-email").param("recoveryEmail", "x@example.com").with(csrf())
                .with(oidcLogin().idToken(t -> t.claim("amr", List.of("mfa")).issuedAt(Instant.now()))))
            .andExpect(redirectedUrl("/account/security"))
            .andExpect(flash().attribute("message", "Recovery email changed to x@example.com"));
    }

    @Test
    void adminRoleOpensAdminPage() throws Exception {
        mvc.perform(get("/admin").with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
            .andExpect(status().isOk());
    }

    @Test
    void apiReadsDoNotNeedMfa() throws Exception {
        mvc.perform(get("/api/me").with(jwt().jwt(j -> j.subject("auth0|42"))))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("auth0|42")));
    }
}
