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
import com.userid.dal.repo.ProfileFieldRepository;
import com.userid.dal.repo.UserRepository;
import com.userid.dal.repo.UserSocialIdentityRepository;
import com.userid.security.DomainUserJwtService;
import com.userid.api.client.EmailNormalizer;
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
  private static final String VK_TOKEN_ENDPOINT = "https://id.vk.ru/oauth2/auth";
  private static final String VK_USERINFO_ENDPOINT = "https://id.vk.ru/oauth2/user_info";

  private final DomainSocialProviderConfigRepository domainSocialProviderConfigRepository;
  private final ProfileFieldRepository profileFieldRepository;
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
    boolean profileCompletionRequired = profileFieldRepository.existsByDomainId(domainId);

    SocialPrincipal socialPrincipal = resolveSocialPrincipal(provider, config, request);

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
        ? resolveOrCreateUser(config.getDomain(), socialPrincipal, profileCompletionRequired)
        : identity.getUser();
    boolean userChanged = syncUserFromSocial(user, socialPrincipal, profileCompletionRequired);
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
      AuthServerSocialLoginRequest request
  ) {
    String code = request.code().trim();
    return switch (provider) {
      case GOOGLE -> resolveGooglePrincipal(config, code);
      case YANDEX -> resolveYandexPrincipal(config, code);
      case VK -> resolveVkPrincipal(config, request);
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
    String email = userInfo == null ? null : normalizeEmail(userInfo.email());
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
    String email = userInfo == null ? null : normalizeEmail(userInfo.defaultEmail());
    if (!StringUtils.hasText(email) && userInfo != null && userInfo.emails() != null) {
      email = userInfo.emails().stream()
          .map(this::normalizeEmail)
          .filter(StringUtils::hasText)
          .findFirst()
          .orElse(null);
    }
    if (!StringUtils.hasText(subject) || !StringUtils.hasText(email)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Yandex user profile is incomplete");
    }

    return new SocialPrincipal(subject, email, true);
  }

  private SocialPrincipal resolveVkPrincipal(DomainSocialProviderConfig config, AuthServerSocialLoginRequest request) {
    requireProviderConfig(config, "VK social provider is not configured");
    String codeVerifier = trimToNull(request.codeVerifier());
    String deviceId = trimToNull(request.deviceId());
    String state = trimToNull(request.state());
    if (!StringUtils.hasText(codeVerifier) || !StringUtils.hasText(deviceId)) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "VK auth payload is incomplete");
    }

    MultiValueMap<String, String> tokenForm = new LinkedMultiValueMap<>();
    tokenForm.add("grant_type", "authorization_code");
    tokenForm.add("code_verifier", codeVerifier);
    tokenForm.add("redirect_uri", config.getCallbackUri());
    tokenForm.add("code", request.code().trim());
    tokenForm.add("client_id", config.getClientId());
    tokenForm.add("device_id", deviceId);
    if (StringUtils.hasText(state)) {
      tokenForm.add("state", state);
    }

    VkTokenResponse tokenResponse;
    try {
      tokenResponse = restClient.post()
          .uri(VK_TOKEN_ENDPOINT)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(tokenForm)
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

    MultiValueMap<String, String> userInfoForm = new LinkedMultiValueMap<>();
    userInfoForm.add("client_id", config.getClientId());
    userInfoForm.add("access_token", tokenResponse.accessToken());

    VkUserInfoResponse userInfoResponse;
    try {
      userInfoResponse = restClient.post()
          .uri(VK_USERINFO_ENDPOINT)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(userInfoForm)
          .retrieve()
          .body(VkUserInfoResponse.class);
    } catch (RestClientException ex) {
      log.warn("VK userinfo failed domainId={} reason={}", config.getDomain().getId(), ex.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Failed to resolve VK user profile");
    }

    Long subjectUserId = tokenResponse.userId();
    String email = null;
    if (userInfoResponse != null && userInfoResponse.user() != null) {
      if (userInfoResponse.user().userId() != null) {
        subjectUserId = userInfoResponse.user().userId();
      }
      email = normalizeEmail(userInfoResponse.user().email());
    }
    String subject = String.valueOf(subjectUserId);

    if (!StringUtils.hasText(email)) {
      throw new ResponseStatusException(
          HttpStatus.UNAUTHORIZED,
          "VK email is unavailable. Add email scope in VK app settings");
    }

    return new SocialPrincipal(subject, email, true);
  }
  private void requireProviderConfig(DomainSocialProviderConfig config, String message) {
    if (!StringUtils.hasText(config.getClientId())
        || !StringUtils.hasText(config.getClientSecret())
        || !StringUtils.hasText(config.getCallbackUri())) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
  }

  private User resolveOrCreateUser(
      Domain domain,
      SocialPrincipal socialPrincipal,
      boolean profileCompletionRequired
  ) {
    return userRepository.findByDomainIdAndEmail(domain.getId(), socialPrincipal.email())
        .or(() -> userRepository.findByDomainIdAndEmailPending(domain.getId(), socialPrincipal.email()))
        .orElseGet(() -> saveUser(User.builder()
            .domain(domain)
            .email(socialPrincipal.email())
            .emailPending(socialPrincipal.email())
            .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
            .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
            .emailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC))
            .active(!profileCompletionRequired)
            .build()));
  }

  private User saveUser(User user) {
    try {
      return userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered");
    }
  }

  private boolean syncUserFromSocial(
      User user,
      SocialPrincipal socialPrincipal,
      boolean profileCompletionRequired
  ) {
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
    if (!profileCompletionRequired && !user.isActive()) {
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

  private String normalizeEmail(String value) {
    return EmailNormalizer.normalizeNullable(value);
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
      @com.fasterxml.jackson.annotation.JsonProperty("id_token")
      String idToken,
      @com.fasterxml.jackson.annotation.JsonProperty("user_id")
      Long userId
  ) {
  }

  private record VkUserInfoResponse(
      VkUserInfo user
  ) {
  }

  private record VkUserInfo(
      @com.fasterxml.jackson.annotation.JsonProperty("user_id")
      Long userId,
      String email
  ) {
  }
}
