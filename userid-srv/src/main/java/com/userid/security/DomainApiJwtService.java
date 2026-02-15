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
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class DomainApiJwtService {
  private final DomainJwtSecretService domainJwtSecretService;
  private final ObjectMapper objectMapper;

  public DomainApiJwtService(DomainJwtSecretService domainJwtSecretService, ObjectMapper objectMapper) {
    this.domainJwtSecretService = domainJwtSecretService;
    this.objectMapper = objectMapper;
  }

  public DomainApiPrincipal parseToken(String token) throws JwtException {
    log.info("Domain API JWT decode start token={}", tokenFingerprint(token));
    Long domainId = extractDomainId(token);
    log.info("Domain API JWT payload extracted domainId={} token={}", domainId, tokenFingerprint(token));
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
    log.info(
        "Domain API JWT claims sub={} domainId={} type={} exp={} token={}",
        claims.getSubject(),
        tokenDomainId,
        type,
        claims.getExpiration(),
        tokenFingerprint(token));
    if (tokenDomainId == null || !tokenDomainId.equals(domainId)) {
      log.warn(
          "Domain API JWT rejected reason=Invalid domainId tokenDomainId={} payloadDomainId={} token={}",
          tokenDomainId,
          domainId,
          tokenFingerprint(token));
      throw new JwtException("Invalid domainId");
    }
    if (type == null || !"domain-api".equals(type)) {
      log.warn("Domain API JWT rejected reason=Invalid token type type={} token={}", type, tokenFingerprint(token));
      throw new JwtException("Invalid token type");
    }
    log.info("Domain API JWT decode success domainId={} token={}", domainId, tokenFingerprint(token));
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
      log.info("Domain API JWT payload json={} token={}", node, tokenFingerprint(token));
      JsonNode domainIdNode = node.get("domainId");
      if (domainIdNode == null || domainIdNode.isNull()) {
        log.warn("Domain API JWT rejected reason=Missing domainId token={}", tokenFingerprint(token));
        throw new JwtException("Missing domainId");
      }
      return domainIdNode.asLong();
    } catch (Exception ex) {
      if (ex instanceof JwtException jwt) {
        throw jwt;
      }
      log.warn("Domain API JWT decode failed reason={} token={}", ex.getMessage(), tokenFingerprint(token));
      throw new JwtException("Invalid token");
    }
  }

  private String tokenFingerprint(String token) {
    if (token == null || token.isBlank()) {
      return "<empty>";
    }
    int visible = Math.min(12, token.length());
    return token.substring(0, visible) + "...(" + token.length() + ")";
  }
}
