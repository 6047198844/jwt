package com.example.jwt.user.domain;

import com.example.jwt.user.constant.UserRole;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class User {
    private String email;
    private String pw;
    private UserRole role;
}
