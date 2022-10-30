package com.example.jwt.user.auth.security;

public interface JwtProperties {
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
    String SECRET_KEY = "SECRET_KEY";
    int REFRESH_TOKEN_EXPIRE_DATE = 30;
    int ACCESS_TOKEN_EXPIRE_DATE = 365;
}