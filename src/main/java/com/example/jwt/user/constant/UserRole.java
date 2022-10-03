package com.example.jwt.user.constant;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum UserRole {
    ROLE_USER("ROLE_USER"),
    ROLE_ADMIN("ROLE_ADMIN");

    private final String role;
}
