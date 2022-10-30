package com.example.jwt.user.ui;

import com.example.jwt.user.application.UserAuthService;
import com.example.jwt.user.application.UserCommonService;
import com.example.jwt.user.auth.TokenItem;
import com.example.jwt.user.auth.TokenService;
import com.example.jwt.user.auth.security.JwtProperties;
import com.example.jwt.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserAuthService userAuthService;
    private final UserCommonService userCommonService;
    private final TokenService tokenService;

    // TODO validate user
    // TODO permission 은 안들어오게 해야함.
    @PostMapping("/join")
    public String join(User user) {
        user.giveUserPermission();
        userAuthService.join(user);
        return "ok";
    }

    @GetMapping("/refresh")
    public TokenItem refresh(final HttpServletRequest request) {
        final String header = request.getHeader(JwtProperties.HEADER_STRING);
        if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            throw new IllegalArgumentException("유저 refresh 토큰이 없습니다.");
        }
        final String refreshToken = request.getHeader(JwtProperties.HEADER_STRING)
                .replace(JwtProperties.TOKEN_PREFIX, "");
        return tokenService.refresh(refreshToken);
    }

    @PostMapping("/user/details")
    public String details(User user) {
        return userCommonService.findByUserName(user.getUsername())
                .map(User::toString)
                .orElse("유저 정보 없음");
    }
}