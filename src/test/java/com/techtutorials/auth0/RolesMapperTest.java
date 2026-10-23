package com.techtutorials.auth0;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

class RolesMapperTest {

    @Test
    void mapsAuth0RolesClaimToSpringRoles() {
        OidcIdToken token = new OidcIdToken("t", Instant.now(), Instant.now().plusSeconds(60),
            Map.of("sub", "auth0|1", SecurityConfig.ROLES_CLAIM, List.of("admin", "editor")));

        var mapped = SecurityConfig.auth0RolesMapper().mapAuthorities(List.of(new OidcUserAuthority(token)));

        assertThat(mapped).extracting(GrantedAuthority::getAuthority)
            .contains("ROLE_ADMIN", "ROLE_EDITOR", "OIDC_USER");
    }
}
