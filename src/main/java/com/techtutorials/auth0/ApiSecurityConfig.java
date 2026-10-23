package com.techtutorials.auth0;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ApiSecurityConfig {

    static final String AMR_CLAIM = "https://example.com/amr";

    @Bean
    @Order(1)
    SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/transfers/**")
                    .access((authentication, context) -> new AuthorizationDecision(hasMfa(authentication.get())))
                .anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> ex.accessDeniedHandler((request, response, denied) -> {
                // RFC 9470: tell the client which authentication level to obtain
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.setHeader("WWW-Authenticate", "Bearer error=\"insufficient_user_authentication\", "
                    + "error_description=\"Multi-factor authentication required\", "
                    + "acr_values=\"" + StepUp.MFA_ACR + "\"");
            }));
        return http.build();
    }

    private static boolean hasMfa(Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken jwt)) {
            return false;
        }
        List<String> amr = jwt.getToken().getClaimAsStringList(AMR_CLAIM);
        return amr != null && amr.contains("mfa");
    }
}
