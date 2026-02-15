package com.userid.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.userid.service.DomainJwtSecretService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

@Service
public class DomainApiJwtService {
  private final DomainJwtSecretService domainJwtSecretService;
  private final ObjectMapper objectMapper;

  public DomainApiJwtService(DomainJwtSecretService domainJwtSecretService, ObjectMapper objectMapper) {
    this.domainJwtSecretService = domainJwtSecretService;
    this.objectMapper = objectMapper;
  }

  public DomainApiPrincipal parseToken(String token) throws JwtException {
    Long domainId = extractDomainId(token);
    String secret = domainJwtSecretService.getSecret(domainId);
    SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    Claims claims = Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();

    Number tokenDomainIdValue = claims.get("domainId", Number.class);
    String type = claims.get("type", String.class);
    Long tokenDomainId = tokenDomainIdValue == null ? null : tokenDomainIdValue.longValue();
    if (tokenDomainId == null || !tokenDomainId.equals(domainId)) {
      throw new JwtException("Invalid domainId");
    }
    if (type == null || !"domain-api".equals(type)) {
      throw new JwtException("Invalid token type");
    }
    return new DomainApiPrincipal(domainId);
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
