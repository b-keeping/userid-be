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
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class DomainUserSocialAuthService {
  private static final String GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
  private static final String GOOGLE_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo";
  private static final String YANDEX_TOKEN_ENDPOINT = "https://oauth.yandex.com/token";
  private static final String YANDEX_USERINFO_ENDPOINT = "https://login.yandex.ru/info?format=json";
  private static final String VK_TOKEN_ENDPOINT = "https://oauth.vk.com/access_token";
  private static final String VK_USERINFO_ENDPOINT = "https://api.vk.com/method/users.get";
  private static final String VK_API_VERSION = "5.199";

  private final DomainSocialProviderConfigRepository domainSocialProviderConfigRepository;
  private final UserSocialIdentityRepository userSocialIdentityRepository;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final DomainUserJwtService domainUserJwtService;
  private final RestClient restClient = RestClient.builder().build();

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
    boolean userChanged = syncUserFromSocial(user, socialPrincipal);
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
    return switch (provider) {
      case GOOGLE -> resolveGooglePrincipal(config, code);
      case YANDEX -> resolveYandexPrincipal(config, code);
      case VK -> resolveVkPrincipal(config, code);
    };
  }

  private SocialPrincipal resolveGooglePrincipal(DomainSocialProviderConfig config, String code) {
    requireProviderConfig(config, "Google social provider is not configured");

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

  private SocialPrincipal resolveYandexPrincipal(DomainSocialProviderConfig config, String code) {
    requireProviderConfig(config, "Yandex social provider is not configured");

    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "authorization_code");
    form.add("code", code);
    form.add("client_id", config.getClientId());
    form.add("client_secret", config.getClientSecret());
    form.add("redirect_uri", config.getCallbackUri());

    YandexTokenResponse tokenResponse;
    try {
      tokenResponse = restClient.post()
          .uri(YANDEX_TOKEN_ENDPOINT)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(form)
          .retrieve()
          .body(YandexTokenResponse.class);
    } catch (RestClientResponseException ex) {
      String body = ex.getResponseBodyAsString();
      if (body != null && body.toLowerCase().contains("invalid_client")) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Yandex social provider config is invalid");
      }
      throw new ResponseStatusException(
          HttpStatus.UNAUTHORIZED,
          "Invalid Yandex authorization code or redirect_uri mismatch");
    } catch (RestClientException ex) {
      log.warn("Yandex token exchange failed domainId={} reason={}", config.getDomain().getId(), ex.getMessage());
      throw new ResponseStatusException(
          HttpStatus.UNAUTHORIZED,
          "Invalid Yandex authorization code or redirect_uri mismatch");
    }

    if (tokenResponse == null || !StringUtils.hasText(tokenResponse.accessToken())) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Yandex token response is invalid");
    }

    YandexUserInfo userInfo;
    try {
      userInfo = restClient.get()
          .uri(YANDEX_USERINFO_ENDPOINT)
          .headers(headers -> headers.set("Authorization", "OAuth " + tokenResponse.accessToken()))
          .retrieve()
          .body(YandexUserInfo.class);
    } catch (RestClientException ex) {
      log.warn("Yandex userinfo failed domainId={} reason={}", config.getDomain().getId(), ex.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Failed to resolve Yandex user profile");
    }

    String subject = userInfo == null ? null : trimToNull(userInfo.id());
    String email = userInfo == null ? null : trimToNull(userInfo.defaultEmail());
    if (!StringUtils.hasText(email) && userInfo != null && userInfo.emails() != null) {
      email = userInfo.emails().stream()
          .map(this::trimToNull)
          .filter(StringUtils::hasText)
          .findFirst()
          .orElse(null);
    }
    if (!StringUtils.hasText(subject) || !StringUtils.hasText(email)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Yandex user profile is incomplete");
    }

    return new SocialPrincipal(subject, email, true);
  }

  private SocialPrincipal resolveVkPrincipal(DomainSocialProviderConfig config, String code) {
    requireProviderConfig(config, "VK social provider is not configured");

    String tokenRequestUri = UriComponentsBuilder.fromUriString(VK_TOKEN_ENDPOINT)
        .queryParam("client_id", config.getClientId())
        .queryParam("client_secret", config.getClientSecret())
        .queryParam("redirect_uri", config.getCallbackUri())
        .queryParam("code", code)
        .build()
        .toUriString();

    VkTokenResponse tokenResponse;
    try {
      tokenResponse = restClient.get()
          .uri(tokenRequestUri)
          .retrieve()
          .body(VkTokenResponse.class);
    } catch (RestClientException ex) {
      log.warn("VK token exchange failed domainId={} reason={}", config.getDomain().getId(), ex.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid VK authorization code");
    }

    if (tokenResponse == null
        || !StringUtils.hasText(tokenResponse.accessToken())
        || tokenResponse.userId() == null) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "VK token response is invalid");
    }

    String subject = String.valueOf(tokenResponse.userId());
    String email = trimToNull(tokenResponse.email());

    String vkProfileUserId = resolveVkProfileUserId(config.getDomain().getId(), tokenResponse);
    if (StringUtils.hasText(vkProfileUserId)) {
      subject = vkProfileUserId;
    }

    if (!StringUtils.hasText(email)) {
      throw new ResponseStatusException(
          HttpStatus.UNAUTHORIZED,
          "VK email is unavailable. Add email scope in VK app settings");
    }

    return new SocialPrincipal(subject, email, true);
  }

  private String resolveVkProfileUserId(Long domainId, VkTokenResponse tokenResponse) {
    String usersUri = UriComponentsBuilder.fromUriString(VK_USERINFO_ENDPOINT)
        .queryParam("user_ids", tokenResponse.userId())
        .queryParam("access_token", tokenResponse.accessToken())
        .queryParam("v", VK_API_VERSION)
        .build()
        .toUriString();

    VkUsersResponse usersResponse;
    try {
      usersResponse = restClient.get()
          .uri(usersUri)
          .retrieve()
          .body(VkUsersResponse.class);
    } catch (RestClientException ex) {
      log.warn("VK userinfo failed domainId={} reason={}", domainId, ex.getMessage());
      return null;
    }

    if (usersResponse == null || usersResponse.response() == null || usersResponse.response().isEmpty()) {
      if (usersResponse != null && usersResponse.error() != null) {
        log.warn(
            "VK userinfo returned API error domainId={} code={} message={}",
            domainId,
            usersResponse.error().errorCode(),
            usersResponse.error().errorMsg());
      }
      return null;
    }

    VkUserInfo first = usersResponse.response().getFirst();
    return first == null || first.id() == null ? null : String.valueOf(first.id());
  }

  private void requireProviderConfig(DomainSocialProviderConfig config, String message) {
    if (!StringUtils.hasText(config.getClientId())
        || !StringUtils.hasText(config.getClientSecret())
        || !StringUtils.hasText(config.getCallbackUri())) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
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
            .active(true)
            .build()));
  }

  private User saveUser(User user) {
    try {
      return userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered");
    }
  }

  private boolean syncUserFromSocial(User user, SocialPrincipal socialPrincipal) {
    boolean changed = false;
    if (!StringUtils.hasText(user.getEmailPending())) {
      user.setEmailPending(socialPrincipal.email());
      changed = true;
    }
    if (!StringUtils.hasText(user.getEmail())) {
      user.setEmail(socialPrincipal.email());
      changed = true;
    }
    if (user.getEmailVerifiedAt() == null) {
      user.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
      changed = true;
    }
    if (!user.isActive()) {
      user.setActive(true);
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
        user.isActive(),
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

  private record YandexTokenResponse(
      @com.fasterxml.jackson.annotation.JsonProperty("access_token")
      String accessToken
  ) {
  }

  private record YandexUserInfo(
      String id,
      @com.fasterxml.jackson.annotation.JsonProperty("default_email")
      String defaultEmail,
      List<String> emails
  ) {
  }

  private record VkTokenResponse(
      @com.fasterxml.jackson.annotation.JsonProperty("access_token")
      String accessToken,
      @com.fasterxml.jackson.annotation.JsonProperty("user_id")
      Long userId,
      String email
  ) {
  }

  private record VkUsersResponse(
      List<VkUserInfo> response,
      VkApiError error
  ) {
  }

  private record VkUserInfo(
      Long id
  ) {
  }

  private record VkApiError(
      @com.fasterxml.jackson.annotation.JsonProperty("error_code")
      Integer errorCode,
      @com.fasterxml.jackson.annotation.JsonProperty("error_msg")
      String errorMsg
  ) {
  }
}
