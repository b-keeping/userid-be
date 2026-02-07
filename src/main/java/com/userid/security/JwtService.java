package com.userid.security;

import com.userid.dal.entity.Owner;
import com.userid.dal.entity.OwnerRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
  private final SecretKey secretKey;
  private final Duration expiration;

  public JwtService(
      @Value("${auth.jwt.secret}") String secret,
      @Value("${auth.jwt.expiration-minutes}") long expirationMinutes
  ) {
    if (secret == null || secret.length() < 32) {
      throw new IllegalStateException("auth.jwt.secret must be at least 32 characters");
    }
    this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    this.expiration = Duration.ofMinutes(expirationMinutes);
  }

  public String generateToken(Owner user) {
    return generateToken(user, expiration);
  }

  public String generateToken(Owner user, Duration customExpiration) {
    Instant now = Instant.now();
    return Jwts.builder()
        .subject(String.valueOf(user.getId()))
        .claim("role", user.getRole().name())
        .claim("email", user.getEmail())
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plus(customExpiration)))
        .signWith(secretKey)
        .compact();
  }

  public AuthPrincipal parseToken(String token) throws JwtException {
    Claims claims = Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();

    Long id = Long.valueOf(claims.getSubject());
    String email = claims.get("email", String.class);
    String roleValue = claims.get("role", String.class);
    OwnerRole role = OwnerRole.valueOf(roleValue);
    return new AuthPrincipal(id, email, role);
  }
}
