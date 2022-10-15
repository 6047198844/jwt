package com.example.jwt.user.ui;

import com.example.jwt.user.application.UserService;
import com.example.jwt.user.auth.TokenService;
import com.example.jwt.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/join")
    public String join(User user) {
        userService.join(user);
        return "ok";
    }

    @PostMapping("/user/details")
    public String details(User user) {
        final Optional<User> userOptional = userService.findByUserName(user.getUsername());
        if (userOptional.isPresent()) {
            return userOptional.get().toString();
        }
        return "유저 정보 없음";
    }
}