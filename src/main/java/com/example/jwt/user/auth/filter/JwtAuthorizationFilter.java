package com.example.jwt.user.auth.filter;

import com.example.jwt.user.application.UserRepository;
import com.example.jwt.user.auth.UserTokenService;
import com.example.jwt.user.domain.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private final UserTokenService userTokenService;
    private final UserRepository userRepository;

    public JwtAuthorizationFilter(final AuthenticationManager authenticationManager, final UserRepository userRepository, final UserTokenService userTokenService) {
        super(authenticationManager);
        this.userTokenService = userTokenService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain chain) throws IOException, ServletException {
        final String header = request.getHeader(JwtProperties.HEADER_STRING);
        if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }
        final String jwt = request.getHeader(JwtProperties.HEADER_STRING)
                .replace(JwtProperties.TOKEN_PREFIX, "");
        final String username = userTokenService.parseUsernameByJwt(jwt);
        if (username != null) {
            final Optional<User> userOptional = userRepository.findByUsername(username);
            if (userOptional.isEmpty()) {
                chain.doFilter(request, response);
                return;
            }
            final User user = userOptional.get();
            final PrincipalDetails principalDetails = new PrincipalDetails(user);
            final Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            principalDetails,
                            null,
                            principalDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }
}