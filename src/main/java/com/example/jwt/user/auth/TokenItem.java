package com.example.jwt.user.auth;

import lombok.Data;

@Data
public class TokenItem {
    private final String accessToken;
    private final String refreshToken;
}
