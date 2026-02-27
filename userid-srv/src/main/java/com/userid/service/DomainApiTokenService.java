package com.userid.service;

import com.userid.api.client.DomainApiJwtTokenUtils;
import com.userid.api.domain.DomainApiTokenResponseDTO;
import java.time.Instant;
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
    long ttlSeconds = expiresSeconds != null ? expiresSeconds : defaultSeconds;
    if (ttlSeconds <= 0) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "expiresSeconds must be positive");
    }
    String secret = domainJwtSecretService.getOrCreateSecret(domainId);
    try {
      DomainApiJwtTokenUtils.DomainApiJwtToken token = DomainApiJwtTokenUtils.generate(
          domainId,
          secret,
          ttlSeconds,
          Instant.now());
      return new DomainApiTokenResponseDTO(token.token(), token.expiresAt());
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage());
    }
  }
}
