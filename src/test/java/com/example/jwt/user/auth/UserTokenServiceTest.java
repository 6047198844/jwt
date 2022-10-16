package com.example.jwt.user.auth;

import com.example.jwt.user.domain.User;
import com.example.jwt.user.domain.constant.UserRole;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserTokenServiceTest {
    private UserTokenService userTokenService = new UserTokenService();

    @Test
    void JWT생성및검증() {
        final User user = User.builder()
                .username("이준수")
                .password("1234a")
                .email("corsair@gmail.com").build();
        user.addRoles(UserRole.ROLE_ADMIN);
        final String jwt = userTokenService.generate(user);
        final String username = userTokenService.parseUsernameByJwt(jwt);
        Assertions.assertThat(username).isEqualTo(user.getUsername());
    }
}