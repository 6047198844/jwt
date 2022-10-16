package com.example.jwt.user.ui;

import com.example.jwt.user.application.UserAuthService;
import com.example.jwt.user.application.UserCommonService;
import com.example.jwt.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserAuthService userAuthService;
    private final UserCommonService userCommonService;

    @PostMapping("/join")
    public String join(User user) {
        userAuthService.join(user);
        return "ok";
    }

    @PostMapping("/user/details")
    public String details(User user) {
        return userCommonService.findByUserName(user.getUsername())
                .map(User::toString)
                .orElse("유저 정보 없음");
    }
}