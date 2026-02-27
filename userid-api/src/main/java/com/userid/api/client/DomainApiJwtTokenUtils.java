package com.userid.api.client;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Objects;
import javax.crypto.SecretKey;

public final class DomainApiJwtTokenUtils {
  private static final String DOMAIN_API_SUBJECT = "domain-api";
  private static final String DOMAIN_API_TYPE = "domain-api";

  private DomainApiJwtTokenUtils() {
  }

  public static DomainApiJwtToken generate(
      Long domainId,
      String secret,
      long ttlSeconds,
      Instant issuedAt
  ) {
    Objects.requireNonNull(domainId, "domainId must not be null");
    Objects.requireNonNull(issuedAt, "issuedAt must not be null");
    if (secret == null || secret.isBlank()) {
      throw new IllegalArgumentException("Domain secret is not initialized");
    }
    if (ttlSeconds <= 0) {
      throw new IllegalArgumentException("ttlSeconds must be positive");
    }
    SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    Instant expiresAt = issuedAt.plusSeconds(ttlSeconds);
    String token = Jwts.builder()
        .subject(DOMAIN_API_SUBJECT)
        .claim("domainId", domainId)
        .claim("type", DOMAIN_API_TYPE)
        .issuedAt(Date.from(issuedAt))
        .expiration(Date.from(expiresAt))
        .signWith(secretKey)
        .compact();
    return new DomainApiJwtToken(token, OffsetDateTime.ofInstant(expiresAt, ZoneOffset.UTC));
  }

  public record DomainApiJwtToken(String token, OffsetDateTime expiresAt) {
  }
}
