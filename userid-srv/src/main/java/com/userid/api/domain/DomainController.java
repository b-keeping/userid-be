package com.userid.api.domain;

import com.userid.api.common.ApiMessageDTO;
import com.userid.api.client.AuthServerSocialProviderEnum;
import com.userid.api.client.DomainSocialProviderConfigRequestDTO;
import com.userid.api.client.DomainSocialProviderConfigResponseDTO;
import com.userid.api.client.UseridApiEndpoints;
import com.userid.api.domain.DomainApiTokenRequestDTO;
import com.userid.api.domain.DomainApiTokenResponseDTO;
import com.userid.api.domain.DomainJwtSecretResponseDTO;
import com.userid.security.AuthPrincipalDTO;
import com.userid.service.DomainService;
import com.userid.service.DomainSocialProviderConfigService;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping(UseridApiEndpoints.DOMAINS_BASE)
@RequiredArgsConstructor
public class DomainController {
  private final DomainService domainService;
  private final DomainSocialProviderConfigService domainSocialProviderConfigService;

  @PostMapping
  public DomainResponseDTO create(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @Valid @RequestBody DomainRequestDTO request
  ) {
    return domainService.create(principal.id(), request);
  }

  @GetMapping
  public List<DomainResponseDTO> list(
      @AuthenticationPrincipal AuthPrincipalDTO principal
  ) {
    return domainService.list(principal.id());
  }

  @PutMapping("/{domainId}")
  public DomainResponseDTO update(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId,
      @RequestBody DomainUpdateRequestDTO request
  ) {
    return domainService.update(principal.id(), domainId, request);
  }

  @PostMapping("/{domainId}/dns-check")
  public DomainResponseDTO dnsCheck(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId
  ) {
    return domainService.checkDns(principal.id(), domainId);
  }

  @PostMapping("/{domainId}/verify")
  public DomainResponseDTO verify(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId
  ) {
    return domainService.verifyDomain(principal.id(), domainId);
  }

  @PostMapping("/{domainId}/smtp-reset")
  public DomainResponseDTO resetSmtp(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId
  ) {
    return domainService.resetSmtp(principal.id(), domainId);
  }

  @GetMapping("/{domainId}/user-jwt-secret")
  public DomainJwtSecretResponseDTO getUserJwtSecret(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId
  ) {
    return domainService.getUserJwtSecret(principal.id(), domainId);
  }

  @PostMapping("/{domainId}/user-jwt-secret/rotate")
  public DomainJwtSecretResponseDTO rotateUserJwtSecret(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId
  ) {
    return domainService.rotateUserJwtSecret(principal.id(), domainId);
  }

  @PostMapping("/{domainId}/domain-api-token")
  public DomainApiTokenResponseDTO domainApiToken(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId,
      @RequestBody DomainApiTokenRequestDTO request
  ) {
    Long expiresSeconds = request == null ? null : request.expiresSeconds();
    return domainService.generateDomainApiToken(principal.id(), domainId, expiresSeconds);
  }

  @GetMapping(UseridApiEndpoints.DOMAIN_SOCIAL_PROVIDER_CONFIG)
  public DomainSocialProviderConfigResponseDTO getSocialProviderConfig(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId,
      @PathVariable String provider
  ) {
    return domainSocialProviderConfigService.get(
        principal.id(),
        domainId,
        parseProvider(provider));
  }

  @PutMapping(UseridApiEndpoints.DOMAIN_SOCIAL_PROVIDER_CONFIG)
  public DomainSocialProviderConfigResponseDTO updateSocialProviderConfig(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId,
      @PathVariable String provider,
      @RequestBody DomainSocialProviderConfigRequestDTO request
  ) {
    return domainSocialProviderConfigService.upsert(
        principal.id(),
        domainId,
        parseProvider(provider),
        request);
  }

  @DeleteMapping("/{domainId}")
  public ApiMessageDTO delete(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId
  ) {
    domainService.delete(principal.id(), domainId);
    return new ApiMessageDTO("ok");
  }

  private AuthServerSocialProviderEnum parseProvider(String provider) {
    try {
      return AuthServerSocialProviderEnum.fromPath(provider);
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage());
    }
  }
}
