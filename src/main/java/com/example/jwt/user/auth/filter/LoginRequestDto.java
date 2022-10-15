package com.example.jwt.user.auth.filter;

import lombok.Data;

@Data
public class LoginRequestDto {
	private String username;
	private String password;
}
