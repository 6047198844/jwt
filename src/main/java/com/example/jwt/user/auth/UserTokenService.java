package com.example.jwt.user.auth;

import com.example.jwt.user.domain.User;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.example.jwt.user.auth.filter.JwtProperties.EXPIRE_DATE;
import static com.example.jwt.user.auth.filter.JwtProperties.SECRET_KEY;

@Slf4j
@Component
public class UserTokenService {
    public String generate(final User user) {
        return Jwts.builder()
                .setHeader(createHeader())
                .setSubject(user.getEmail())
                .setClaims(createClaims(user))
                .setExpiration(createExpireDate())
                .signWith(SignatureAlgorithm.HS256, createSigningKey())
                .compact();
    }

    public String parseUsernameByJwt(final String token) {
        return this.getClaims(token)
                .get("username", String.class);
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
        claims.put("username", user.getUsername());
        claims.put("roles", user.getRoles());
        return claims;
    }

    private Date createExpireDate() {
        final Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, EXPIRE_DATE);
        return calendar.getTime();
    }


    private Key createSigningKey() {
        final byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
        return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
    }
}