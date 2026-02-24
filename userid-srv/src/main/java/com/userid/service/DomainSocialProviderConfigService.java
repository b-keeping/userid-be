package com.userid.service;

import com.userid.api.client.AuthServerSocialProviderEnum;
import com.userid.api.client.DomainSocialProviderConfigRequestDTO;
import com.userid.api.client.DomainSocialProviderConfigResponseDTO;
import com.userid.dal.entity.DomainEntity;
import com.userid.dal.entity.DomainSocialProviderConfigEntity;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.DomainSocialProviderConfigRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class DomainSocialProviderConfigService {
  private final AccessService accessService;
  private final DomainRepository domainRepository;
  private final DomainSocialProviderConfigRepository domainSocialProviderConfigRepository;

  public DomainSocialProviderConfigResponseDTO get(
      Long ownerId,
      Long domainId,
      AuthServerSocialProviderEnum provider
  ) {
    accessService.requireDomainAccess(ownerId, domainId);

    DomainSocialProviderConfigEntity config = domainSocialProviderConfigRepository
        .findByDomainIdAndProvider(domainId, provider)
        .orElse(null);
    if (config == null) {
      return new DomainSocialProviderConfigResponseDTO(
          provider.pathValue(),
          false,
          null,
          false,
          null
      );
    }
    return toResponse(config);
  }

  public DomainSocialProviderConfigResponseDTO getForDomainApi(
      Long domainId,
      AuthServerSocialProviderEnum provider
  ) {
    DomainSocialProviderConfigEntity config = domainSocialProviderConfigRepository
        .findByDomainIdAndProvider(domainId, provider)
        .orElse(null);
    if (config == null || !Boolean.TRUE.equals(config.getEnabled())) {
      return new DomainSocialProviderConfigResponseDTO(
          provider.pathValue(),
          false,
          null,
          false,
          null
      );
    }
    return toResponse(config);
  }

  public DomainSocialProviderConfigResponseDTO upsert(
      Long ownerId,
      Long domainId,
      AuthServerSocialProviderEnum provider,
      DomainSocialProviderConfigRequestDTO request
  ) {
    accessService.requireDomainAccess(ownerId, domainId);

    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    DomainSocialProviderConfigEntity config = domainSocialProviderConfigRepository
        .findByDomainIdAndProvider(domainId, provider)
        .orElseGet(() -> DomainSocialProviderConfigEntity.builder()
            .domain(domain)
            .provider(provider)
            .enabled(false)
            .build());

    boolean enabled = request != null && Boolean.TRUE.equals(request.enabled());
    config.setEnabled(enabled);
    config.setClientId(trimToNull(request == null ? null : request.clientId()));
    config.setCallbackUri(trimToNull(request == null ? null : request.callbackUri()));
    if (request != null && request.clientSecret() != null) {
      config.setClientSecret(trimToNull(request.clientSecret()));
    }
    if (enabled) {
      validateEnabledConfig(config);
    }

    DomainSocialProviderConfigEntity saved = domainSocialProviderConfigRepository.save(config);
    return toResponse(saved);
  }

  private DomainSocialProviderConfigResponseDTO toResponse(DomainSocialProviderConfigEntity config) {
    return new DomainSocialProviderConfigResponseDTO(
        config.getProvider().pathValue(),
        Boolean.TRUE.equals(config.getEnabled()),
        config.getClientId(),
        StringUtils.hasText(config.getClientSecret()),
        config.getCallbackUri()
    );
  }

  private void validateEnabledConfig(DomainSocialProviderConfigEntity config) {
    if (!StringUtils.hasText(config.getClientId())
        || !StringUtils.hasText(config.getClientSecret())
        || !StringUtils.hasText(config.getCallbackUri())) {
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST,
          "Enabled social provider config requires clientId, clientSecret and callbackUri");
    }
  }

  private String trimToNull(String value) {
    if (!StringUtils.hasText(value)) {
      return null;
    }
    return value.trim();
  }
}
