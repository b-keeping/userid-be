package com.userid.service;

import com.userid.api.client.AuthServerSocialLoginRequest;
import com.userid.api.client.AuthServerSocialProvider;
import com.userid.api.user.UserAuthResponse;
import com.userid.api.user.UserLoginResponse;
import com.userid.dal.entity.Domain;
import com.userid.dal.entity.DomainSocialProviderConfig;
import com.userid.dal.entity.User;
import com.userid.dal.entity.UserSocialIdentity;
import com.userid.dal.repo.DomainSocialProviderConfigRepository;
import com.userid.dal.repo.UserRepository;
import com.userid.dal.repo.UserSocialIdentityRepository;
import com.userid.security.DomainUserJwtService;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class DomainUserSocialAuthService {
  private static final String GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
  private static final String GOOGLE_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo";

  private final DomainSocialProviderConfigRepository domainSocialProviderConfigRepository;
  private final UserSocialIdentityRepository userSocialIdentityRepository;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final DomainUserJwtService domainUserJwtService;
  private final RestClient restClient = RestClient.builder().build();

  @Transactional
  public UserLoginResponse login(
      Long domainId,
      AuthServerSocialProvider provider,
      AuthServerSocialLoginRequest request
  ) {
    String code = request == null ? null : request.code();
    if (!StringUtils.hasText(code)) {
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

    SocialPrincipal socialPrincipal = resolveSocialPrincipal(provider, config, code.trim());

    log.info(
        "Social login resolved principal domainId={} provider={} subject={} email={}",
        domainId,
        provider.pathValue(),
        socialPrincipal.subject(),
        socialPrincipal.email());

    UserSocialIdentity identity = userSocialIdentityRepository
        .findByDomainIdAndProviderAndProviderSubject(domainId, provider, socialPrincipal.subject())
        .orElse(null);
    User user = identity == null
        ? resolveOrCreateUser(config.getDomain(), socialPrincipal)
        : identity.getUser();
    boolean userChanged = syncUserEmailFromSocial(user, socialPrincipal);
    if (userChanged) {
      user = saveUser(user);
    }

    UserSocialIdentity linkedIdentity = identity == null
        ? createIdentity(user, config.getDomain(), provider, socialPrincipal)
        : identity;
    updateIdentity(linkedIdentity, socialPrincipal);
    userSocialIdentityRepository.save(linkedIdentity);

    String token = domainUserJwtService.generateToken(user);
    return new UserLoginResponse(token, toAuthResponse(user));
  }

  private SocialPrincipal resolveSocialPrincipal(
      AuthServerSocialProvider provider,
      DomainSocialProviderConfig config,
      String code
  ) {
    if (provider == AuthServerSocialProvider.GOOGLE) {
      return resolveGooglePrincipal(config, code);
    }
    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported social provider");
  }

  private SocialPrincipal resolveGooglePrincipal(DomainSocialProviderConfig config, String code) {
    if (!StringUtils.hasText(config.getClientId())
        || !StringUtils.hasText(config.getClientSecret())
        || !StringUtils.hasText(config.getCallbackUri())) {
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST,
          "Google social provider is not configured");
    }

    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("code", code);
    form.add("client_id", config.getClientId());
    form.add("client_secret", config.getClientSecret());
    form.add("redirect_uri", config.getCallbackUri());
    form.add("grant_type", "authorization_code");

    GoogleTokenResponse tokenResponse;
    try {
      tokenResponse = restClient.post()
          .uri(GOOGLE_TOKEN_ENDPOINT)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(form)
          .retrieve()
          .body(GoogleTokenResponse.class);
    } catch (RestClientException ex) {
      log.warn("Google token exchange failed domainId={} reason={}", config.getDomain().getId(), ex.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Google authorization code");
    }

    if (tokenResponse == null || !StringUtils.hasText(tokenResponse.accessToken())) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Google token response is invalid");
    }

    GoogleUserInfo userInfo;
    try {
      userInfo = restClient.get()
          .uri(GOOGLE_USERINFO_ENDPOINT)
          .headers(headers -> headers.setBearerAuth(tokenResponse.accessToken()))
          .retrieve()
          .body(GoogleUserInfo.class);
    } catch (RestClientException ex) {
      log.warn("Google userinfo failed domainId={} reason={}", config.getDomain().getId(), ex.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Failed to resolve Google user profile");
    }

    String subject = userInfo == null ? null : trimToNull(userInfo.sub());
    String email = userInfo == null ? null : trimToNull(userInfo.email());
    boolean emailVerified = userInfo != null && Boolean.TRUE.equals(userInfo.emailVerified());
    if (!StringUtils.hasText(subject) || !StringUtils.hasText(email)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Google user profile is incomplete");
    }
    if (!emailVerified) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Google email is not verified");
    }

    return new SocialPrincipal(subject, email, true);
  }

  private User resolveOrCreateUser(Domain domain, SocialPrincipal socialPrincipal) {
    return userRepository.findByDomainIdAndEmail(domain.getId(), socialPrincipal.email())
        .or(() -> userRepository.findByDomainIdAndEmailPending(domain.getId(), socialPrincipal.email()))
        .orElseGet(() -> saveUser(User.builder()
            .domain(domain)
            .email(socialPrincipal.email())
            .emailPending(socialPrincipal.email())
            .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
            .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
            .emailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC))
            .build()));
  }

  private User saveUser(User user) {
    try {
      return userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered");
    }
  }

  private boolean syncUserEmailFromSocial(User user, SocialPrincipal socialPrincipal) {
    boolean changed = false;
    if (!StringUtils.hasText(user.getEmailPending())) {
      user.setEmailPending(socialPrincipal.email());
      changed = true;
    }
    if (!StringUtils.hasText(user.getEmail())) {
      user.setEmail(socialPrincipal.email());
      changed = true;
    }
    if (socialPrincipal.emailVerified() && user.getEmailVerifiedAt() == null) {
      user.setEmailPending(socialPrincipal.email());
      user.setEmail(socialPrincipal.email());
      user.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
      changed = true;
    }
    return changed;
  }

  private UserSocialIdentity createIdentity(
      User user,
      Domain domain,
      AuthServerSocialProvider provider,
      SocialPrincipal socialPrincipal
  ) {
    return UserSocialIdentity.builder()
        .user(user)
        .domain(domain)
        .provider(provider)
        .providerSubject(socialPrincipal.subject())
        .providerEmail(socialPrincipal.email())
        .providerEmailVerified(socialPrincipal.emailVerified())
        .build();
  }

  private void updateIdentity(UserSocialIdentity identity, SocialPrincipal socialPrincipal) {
    identity.setProviderEmail(socialPrincipal.email());
    identity.setProviderEmailVerified(socialPrincipal.emailVerified());
  }

  private UserAuthResponse toAuthResponse(User user) {
    return new UserAuthResponse(
        user.getId(),
        user.getDomain().getId(),
        user.getEmail(),
        user.getEmailVerifiedAt() != null,
        user.getCreatedAt());
  }

  private String trimToNull(String value) {
    if (!StringUtils.hasText(value)) {
      return null;
    }
    return value.trim();
  }

  private record SocialPrincipal(String subject, String email, boolean emailVerified) {
  }

  private record GoogleTokenResponse(
      @com.fasterxml.jackson.annotation.JsonProperty("access_token")
      String accessToken
  ) {
  }

  private record GoogleUserInfo(
      String sub,
      String email,
      @com.fasterxml.jackson.annotation.JsonProperty("email_verified")
      Boolean emailVerified
  ) {
  }
}
