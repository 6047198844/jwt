package com.example.jwt.user.auth;

import com.example.jwt.user.domain.User;
import com.example.jwt.user.domain.constant.UserRole;
import com.example.jwt.user.infrastructure.UserRepositoryImpl;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class UserTokenServiceTest {
    private TokenService tokenService = new TokenService(new UserRepositoryImpl());

    @Test
    void JWT생성및검증() {
        final User user = User.builder()
                .username("이준수")
                .password("1234a")
                .email("corsair@gmail.com").build();
        user.addRoles(UserRole.ROLE_ADMIN);
        final String jwt = tokenService.generateAccessToken(user);
        final String username = tokenService.parseUsernameByJwt(jwt);
        Assertions.assertThat(username).isEqualTo(user.getUsername());
    }
}