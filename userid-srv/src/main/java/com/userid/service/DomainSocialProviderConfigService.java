package com.userid.service;

import com.userid.api.client.AuthServerSocialProvider;
import com.userid.api.client.DomainSocialProviderConfigRequest;
import com.userid.api.client.DomainSocialProviderConfigResponse;
import com.userid.dal.entity.Domain;
import com.userid.dal.entity.DomainSocialProviderConfig;
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

  public DomainSocialProviderConfigResponse get(
      Long ownerId,
      Long domainId,
      AuthServerSocialProvider provider
  ) {
    accessService.requireDomainAccess(ownerId, domainId);

    DomainSocialProviderConfig config = domainSocialProviderConfigRepository
        .findByDomainIdAndProvider(domainId, provider)
        .orElse(null);
    if (config == null) {
      return new DomainSocialProviderConfigResponse(
          provider.pathValue(),
          false,
          null,
          false,
          null
      );
    }
    return toResponse(config);
  }

  public DomainSocialProviderConfigResponse upsert(
      Long ownerId,
      Long domainId,
      AuthServerSocialProvider provider,
      DomainSocialProviderConfigRequest request
  ) {
    accessService.requireDomainAccess(ownerId, domainId);

    Domain domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    DomainSocialProviderConfig config = domainSocialProviderConfigRepository
        .findByDomainIdAndProvider(domainId, provider)
        .orElseGet(() -> DomainSocialProviderConfig.builder()
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

    DomainSocialProviderConfig saved = domainSocialProviderConfigRepository.save(config);
    return toResponse(saved);
  }

  private DomainSocialProviderConfigResponse toResponse(DomainSocialProviderConfig config) {
    return new DomainSocialProviderConfigResponse(
        config.getProvider().pathValue(),
        Boolean.TRUE.equals(config.getEnabled()),
        config.getClientId(),
        StringUtils.hasText(config.getClientSecret()),
        config.getCallbackUri()
    );
  }

  private void validateEnabledConfig(DomainSocialProviderConfig config) {
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
