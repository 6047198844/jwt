package com.example.jwt.user.auth;

import com.example.jwt.user.application.UserRepository;
import com.example.jwt.user.domain.User;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.*;

import static com.example.jwt.user.auth.security.JwtProperties.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenService {
    private final UserRepository userRepository;

    public TokenItem refresh(String refreshToken) {
        final String username = this.parseUsernameByJwt(refreshToken);
        final User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("유저가 존재하지 않습니다."));

        if (user.getRefreshToken().equals(refreshToken)) {
            return new TokenItem(generateAccessToken(user), generateRefreshToken(user));
        }
        throw new IllegalArgumentException("유저 refreshToekn 과 일치하지 않습니다.");
    }

    public String generateRefreshToken(final User user) {
        return Jwts.builder()
                .setHeader(createHeader())
                .setSubject(user.getUsername())
                .setExpiration(createRefreshTokenExpireDate())
                .signWith(SignatureAlgorithm.HS256, createSigningKey())
                .compact();
    }

    public String generateAccessToken(final User user) {
        return Jwts.builder()
                .setHeader(createHeader())
                .setSubject(user.getUsername())
                .setClaims(createClaims(user))
                .setExpiration(createAccessTokenExpireDate())
                .signWith(SignatureAlgorithm.HS256, createSigningKey())
                .compact();
    }

    public String parseUsernameByJwt(final String token) {
        return this.getClaims(token)
                .get("sub", String.class);
    }

    private Claims getClaims(final String token) {
        try {
            return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
        } catch (SignatureException ex) {
            log.error("Invalid JWT signature");
            throw ex;
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
            throw ex;
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
            throw ex;
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
            throw ex;
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty.");
            throw ex;
        }
    }

    private Map<String, Object> createHeader() {
        final Map<String, Object> header = new HashMap<>();
        header.put("typ", "JWT");
        header.put("alg", "HS256");
        header.put("regDate", System.currentTimeMillis());
        return header;
    }
    private Map<String, Object> createClaims(final User user) {
        final Map<String, Object> claims = new HashMap<>();
        claims.put("roles", user.getRoles());
        claims.put("email", user.getEmail());
        return claims;
    }

    private Date createAccessTokenExpireDate() {
        final Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, ACCESS_TOKEN_EXPIRE_DATE);
        return calendar.getTime();
    }

    private Date createRefreshTokenExpireDate() {
        final Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, REFRESH_TOKEN_EXPIRE_DATE);
        return calendar.getTime();
    }

    private Key createSigningKey() {
        final byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
        return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
    }
}