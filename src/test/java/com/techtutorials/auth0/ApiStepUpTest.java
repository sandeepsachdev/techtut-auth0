package com.techtutorials.auth0;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class ApiStepUpTest {

    @Autowired
    MockMvc mvc;

    @Test
    void tokenWithoutMfaGetsStepUpChallenge() throws Exception {
        mvc.perform(post("/api/transfers").with(jwt().jwt(j -> j.claim(ApiSecurityConfig.AMR_CLAIM, List.of("pwd")))))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string("WWW-Authenticate", containsString("insufficient_user_authentication")));
    }

    @Test
    void tokenWithMfaIsAccepted() throws Exception {
        mvc.perform(post("/api/transfers").with(jwt().jwt(j -> j.claim(ApiSecurityConfig.AMR_CLAIM, List.of("pwd", "mfa")))))
            .andExpect(status().isOk());
    }

    @Test
    void missingTokenIs401() throws Exception {
        mvc.perform(post("/api/transfers")).andExpect(status().isUnauthorized());
    }
}
