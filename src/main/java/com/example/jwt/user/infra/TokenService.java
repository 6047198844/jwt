package com.example.jwt.user.infra;

import com.example.jwt.user.domain.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class TokenService {
    private static final String SECRET_KEY = "암호키";
    private static final int EXPIRE_DATE = 30;

    public String generateJwtToken(User user) {
        return Jwts.builder()
                .setSubject(user.getEmail())
                .setHeader(createHeader())
                .setClaims(createClaims(user))
                .setExpiration(createExpireDateForOneMonth())
                .signWith(SignatureAlgorithm.HS256, createSigningKey())
                .compact();
    }

    private Map<String, Object> createHeader() {
        return Map.of(
                "typ", "JWT",
                "alg", "HS256",
                "regDate", System.currentTimeMillis());
    }
    private Map<String, Object> createClaims(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", user.getEmail());
        claims.put("role", user.getRole());
        return claims;
    }

    private Date createExpireDateForOneMonth() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, EXPIRE_DATE);
        return calendar.getTime();
    }


    private static Key createSigningKey() {
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
        return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
    }
}