package com.example.jwt.user.auth.filter;

public interface JwtProperties {
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
    String SECRET_KEY = "SECRET_KEY";
    int EXPIRE_DATE = 30;
}