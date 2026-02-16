package com.userid.service;

import com.userid.api.client.AuthServerSocialLoginRequest;
import com.userid.api.client.AuthServerSocialProvider;
import com.userid.api.user.UserLoginResponse;
import com.userid.dal.entity.DomainSocialProviderConfig;
import com.userid.dal.repo.DomainSocialProviderConfigRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class DomainUserSocialAuthService {
  private final DomainSocialProviderConfigRepository domainSocialProviderConfigRepository;

  public UserLoginResponse login(
      Long domainId,
      AuthServerSocialProvider provider,
      AuthServerSocialLoginRequest request
  ) {
    if (request == null || !StringUtils.hasText(request.code())) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social auth code is required");
    }

    DomainSocialProviderConfig config = domainSocialProviderConfigRepository
        .findByDomainIdAndProvider(domainId, provider)
        .orElseThrow(() -> new ResponseStatusException(
            HttpStatus.BAD_REQUEST,
            "Social provider is not configured for this domain"));
    if (!Boolean.TRUE.equals(config.getEnabled())) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social provider is disabled for this domain");
    }

    log.info(
        "Social login requested domainId={} provider={} callbackUri={}",
        domainId,
        provider.pathValue(),
        config.getCallbackUri());

    // Skeleton: Google code exchange and provider profile resolution will be implemented here.
    throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED, "Social login flow is not implemented yet");
  }
}
