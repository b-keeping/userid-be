package com.userid.service;

import com.userid.dal.entity.DomainEntity;
import com.userid.dal.repo.DomainRepository;
import java.security.SecureRandom;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@Service
@RequiredArgsConstructor
public class DomainJwtSecretService {
  private final DomainRepository domainRepository;
  private final SecureRandom random = new SecureRandom();

  public String getOrCreateSecret(DomainEntity domain) {
    String secret = domain.getUserJwtSecret();
    if (secret != null && !secret.isBlank()) {
      return secret;
    }
    String generated = generateSecret();
    domain.setUserJwtSecret(generated);
    domainRepository.save(domain);
    return generated;
  }

  public String getSecret(Long domainId) {
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    String secret = domain.getUserJwtSecret();
    if (secret == null || secret.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Domain secret is not initialized");
    }
    return secret;
  }

  public String getOrCreateSecret(Long domainId) {
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    return getOrCreateSecret(domain);
  }

  public String rotateSecret(Long domainId) {
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    String generated = generateSecret();
    domain.setUserJwtSecret(generated);
    domainRepository.save(domain);
    return generated;
  }

  private String generateSecret() {
    byte[] bytes = new byte[48];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
