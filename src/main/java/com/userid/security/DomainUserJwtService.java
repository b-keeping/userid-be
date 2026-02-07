package com.userid.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.userid.dal.entity.User;
import com.userid.service.DomainJwtSecretService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DomainUserJwtService {
  private final Duration expiration;
  private final DomainJwtSecretService domainJwtSecretService;
  private final ObjectMapper objectMapper;

  public DomainUserJwtService(
      DomainJwtSecretService domainJwtSecretService,
      ObjectMapper objectMapper,
      @Value("${auth.user-jwt.expiration-minutes:60}") long expirationMinutes
  ) {
    this.expiration = Duration.ofMinutes(expirationMinutes);
    this.domainJwtSecretService = domainJwtSecretService;
    this.objectMapper = objectMapper;
  }

  public String generateToken(User user) {
    Instant now = Instant.now();
    String secret = domainJwtSecretService.getOrCreateSecret(user.getDomain());
    SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    return Jwts.builder()
        .subject(String.valueOf(user.getId()))
        .claim("domainId", user.getDomain().getId())
        .claim("email", user.getEmail())
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plus(expiration)))
        .signWith(secretKey)
        .compact();
  }

  public DomainUserPrincipal parseToken(String token) throws JwtException {
    Long domainId = extractDomainId(token);
    String secret = domainJwtSecretService.getSecret(domainId);
    SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    Claims claims = Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();

    Long id = Long.valueOf(claims.getSubject());
    Long tokenDomainId = claims.get("domainId", Long.class);
    String email = claims.get("email", String.class);
    if (tokenDomainId == null || !tokenDomainId.equals(domainId)) {
      throw new JwtException("Invalid domainId");
    }
    return new DomainUserPrincipal(id, tokenDomainId, email);
  }

  private Long extractDomainId(String token) {
    try {
      String[] parts = token.split("\\.");
      if (parts.length < 2) {
        throw new JwtException("Invalid token");
      }
      byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
      JsonNode node = objectMapper.readTree(payload);
      JsonNode domainIdNode = node.get("domainId");
      if (domainIdNode == null || domainIdNode.isNull()) {
        throw new JwtException("Missing domainId");
      }
      return domainIdNode.asLong();
    } catch (Exception ex) {
      if (ex instanceof JwtException jwt) {
        throw jwt;
      }
      throw new JwtException("Invalid token");
    }
  }
}
