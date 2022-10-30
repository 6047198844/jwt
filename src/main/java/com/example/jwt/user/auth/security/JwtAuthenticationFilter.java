package com.example.jwt.user.auth.security;

import com.example.jwt.user.application.UserAuthService;
import com.example.jwt.user.auth.TokenItem;
import com.example.jwt.user.auth.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
            throws AuthenticationException {
        final ObjectMapper objectMapper = new ObjectMapper();
        final LoginRequest loginRequest;
        try {
            loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        final UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword());
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(final HttpServletRequest request,
                                            final HttpServletResponse response,
                                            final FilterChain chain,
                                            final Authentication authResult) throws IOException {
        final PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        final String accessToken = tokenService.generateAccessToken(principalDetails.getUser());
        final String refreshToken = tokenService.generateRefreshToken(principalDetails.getUser());
        principalDetails.getUser().setRefreshToken(refreshToken);

        final TokenItem tokenItem = new TokenItem(accessToken, refreshToken);
        final ObjectMapper objectMapper = new ObjectMapper();
        final String jsonTokenItem = objectMapper.writeValueAsString(tokenItem);
        new ObjectMapper().writeValue(response.getWriter(), jsonTokenItem);
    }

    @Data
    private static class LoginRequest {
        private String username;
        private String password;
    }
}