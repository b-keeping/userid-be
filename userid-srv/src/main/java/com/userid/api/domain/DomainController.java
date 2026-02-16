package com.userid.api.domain;

import com.userid.api.common.ApiMessage;
import com.userid.api.client.AuthServerSocialProvider;
import com.userid.api.client.DomainSocialProviderConfigRequest;
import com.userid.api.client.DomainSocialProviderConfigResponse;
import com.userid.api.client.UseridApiEndpoints;
import com.userid.api.domain.DomainApiTokenRequest;
import com.userid.api.domain.DomainApiTokenResponse;
import com.userid.api.domain.DomainJwtSecretResponse;
import com.userid.security.AuthPrincipal;
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
  public DomainResponse create(
      @AuthenticationPrincipal AuthPrincipal principal,
      @Valid @RequestBody DomainRequest request
  ) {
    return domainService.create(principal.id(), request);
  }

  @GetMapping
  public List<DomainResponse> list(
      @AuthenticationPrincipal AuthPrincipal principal
  ) {
    return domainService.list(principal.id());
  }

  @PutMapping("/{domainId}")
  public DomainResponse update(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId,
      @RequestBody DomainUpdateRequest request
  ) {
    return domainService.update(principal.id(), domainId, request);
  }

  @PostMapping("/{domainId}/dns-check")
  public DomainResponse dnsCheck(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    return domainService.checkDns(principal.id(), domainId);
  }

  @PostMapping("/{domainId}/verify")
  public DomainResponse verify(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    return domainService.verifyDomain(principal.id(), domainId);
  }

  @PostMapping("/{domainId}/smtp-reset")
  public DomainResponse resetSmtp(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    return domainService.resetSmtp(principal.id(), domainId);
  }

  @GetMapping("/{domainId}/user-jwt-secret")
  public DomainJwtSecretResponse getUserJwtSecret(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    return domainService.getUserJwtSecret(principal.id(), domainId);
  }

  @PostMapping("/{domainId}/user-jwt-secret/rotate")
  public DomainJwtSecretResponse rotateUserJwtSecret(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    return domainService.rotateUserJwtSecret(principal.id(), domainId);
  }

  @PostMapping("/{domainId}/domain-api-token")
  public DomainApiTokenResponse domainApiToken(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId,
      @RequestBody DomainApiTokenRequest request
  ) {
    Long expiresSeconds = request == null ? null : request.expiresSeconds();
    return domainService.generateDomainApiToken(principal.id(), domainId, expiresSeconds);
  }

  @GetMapping(UseridApiEndpoints.DOMAIN_SOCIAL_PROVIDER_CONFIG)
  public DomainSocialProviderConfigResponse getSocialProviderConfig(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId,
      @PathVariable String provider
  ) {
    return domainSocialProviderConfigService.get(
        principal.id(),
        domainId,
        parseProvider(provider));
  }

  @PutMapping(UseridApiEndpoints.DOMAIN_SOCIAL_PROVIDER_CONFIG)
  public DomainSocialProviderConfigResponse updateSocialProviderConfig(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId,
      @PathVariable String provider,
      @RequestBody DomainSocialProviderConfigRequest request
  ) {
    return domainSocialProviderConfigService.upsert(
        principal.id(),
        domainId,
        parseProvider(provider),
        request);
  }

  @DeleteMapping("/{domainId}")
  public ApiMessage delete(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    domainService.delete(principal.id(), domainId);
    return new ApiMessage("ok");
  }

  private AuthServerSocialProvider parseProvider(String provider) {
    try {
      return AuthServerSocialProvider.fromPath(provider);
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage());
    }
  }
}
