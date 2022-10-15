package com.example.jwt.user.ui;

import com.example.jwt.user.auth.TokenService;
import com.example.jwt.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final TokenService tokenService;

    @PostMapping("/token")
    public String generateToken(User user) {
        return tokenService.generate(user);
    }
}