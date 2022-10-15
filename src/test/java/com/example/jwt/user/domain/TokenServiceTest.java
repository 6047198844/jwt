package com.example.jwt.user.domain;

import com.example.jwt.user.auth.TokenService;
import com.example.jwt.user.domain.constant.UserRole;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class TokenServiceTest {

    @Test
    void generateToken() {
        final User user = User.builder()
                .username("이준수")
                .password("1234a")
                .email("corsair@gmail.com").build();
        user.addRoles(UserRole.ROLE_ADMIN);
        final TokenService tokenService = new TokenService();
        final String token = tokenService.generate(user);
        Assertions.assertThat(tokenService.getUsername(token)).isEqualTo("이준수");
    }
}