package com.userid.service;

import com.userid.api.domain.DomainApiTokenResponseDTO;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class DomainApiTokenService {
  private final DomainJwtSecretService domainJwtSecretService;
  private final long defaultSeconds;

  public DomainApiTokenService(
      DomainJwtSecretService domainJwtSecretService,
      @Value("${auth.domain-api.default-seconds:86400}") long defaultSeconds
  ) {
    this.domainJwtSecretService = domainJwtSecretService;
    this.defaultSeconds = defaultSeconds;
  }

  public DomainApiTokenResponseDTO generate(Long domainId, Long expiresSeconds) {
    long seconds = expiresSeconds != null ? expiresSeconds : defaultSeconds;
    if (seconds <= 0) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "expiresSeconds must be positive");
    }
    String secret = domainJwtSecretService.getOrCreateSecret(domainId);
    SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    Instant now = Instant.now();
    Instant exp = now.plusSeconds(seconds);
    String token = Jwts.builder()
        .subject("domain-api")
        .claim("domainId", domainId)
        .claim("type", "domain-api")
        .issuedAt(Date.from(now))
        .expiration(Date.from(exp))
        .signWith(secretKey)
        .compact();
    return new DomainApiTokenResponseDTO(token, OffsetDateTime.ofInstant(exp, ZoneOffset.UTC));
  }
}
