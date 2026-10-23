package com.techtutorials.auth0;

import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** Example API: any valid token can read, only an MFA token can transfer. */
@RestController
public class TransferController {

    @GetMapping("/api/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("sub", jwt.getSubject());
    }

    @PostMapping("/api/transfers")
    public Map<String, Object> transfer(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("status", "accepted", "by", jwt.getSubject());
    }
}
