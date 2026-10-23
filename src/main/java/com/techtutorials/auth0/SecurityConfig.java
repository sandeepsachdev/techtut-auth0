package com.techtutorials.auth0;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
public class SecurityConfig {

    static final String ROLES_CLAIM = "https://example.com/roles";

    @Bean
    @Order(2)
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            ClientRegistrationRepository clients,
                                            StepUpAuthorizationManager stepUp) throws Exception {
        // Pages that need a recent MFA challenge
        RequestMatcher stepUpPaths = new OrRequestMatcher(
            PathPatternRequestMatcher.withDefaults().matcher("/account/security/**"),
            PathPatternRequestMatcher.withDefaults().matcher("/payments/**"));

        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/error", "/css/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers(stepUpPaths).access(stepUp)
                .anyRequest().authenticated())
            .oauth2Login(login -> login
                .authorizationEndpoint(endpoint -> endpoint
                    .authorizationRequestResolver(new StepUpAuthorizationRequestResolver(clients)))
                .userInfoEndpoint(userInfo -> userInfo
                    .userAuthoritiesMapper(auth0RolesMapper())))
            .exceptionHandling(ex -> ex
                .accessDeniedHandler(new StepUpAccessDeniedHandler(stepUp, stepUpPaths)))
            .logout(logout -> logout
                .logoutSuccessHandler(oidcLogoutSuccessHandler(clients)));
        return http.build();
    }

    /** Turns the roles an Auth0 Action adds to the ID token into ROLE_* authorities. */
    static GrantedAuthoritiesMapper auth0RolesMapper() {
        return authorities -> {
            Set<GrantedAuthority> mapped = new HashSet<>(authorities);
            for (GrantedAuthority authority : authorities) {
                if (authority instanceof OidcUserAuthority oidc) {
                    List<String> roles = oidc.getIdToken().getClaimAsStringList(ROLES_CLAIM);
                    if (roles != null) {
                        roles.forEach(role -> mapped.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase(Locale.ROOT))));
                    }
                }
            }
            return mapped;
        };
    }

    /** Ends the Auth0 session too, then returns to the home page. */
    private OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clients) {
        OidcClientInitiatedLogoutSuccessHandler handler = new OidcClientInitiatedLogoutSuccessHandler(clients);
        handler.setPostLogoutRedirectUri("{baseUrl}/");
        return handler;
    }
}
