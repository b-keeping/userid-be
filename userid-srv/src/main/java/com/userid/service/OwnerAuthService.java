package com.userid.service;

import com.userid.api.auth.OwnerLoginRequest;
import com.userid.api.auth.OwnerLoginResponse;
import com.userid.api.auth.OwnerPasswordResetConfirmRequest;
import com.userid.api.auth.OwnerPasswordResetRequest;
import com.userid.api.auth.OwnerRegisterRequest;
import com.userid.api.auth.OwnerSocialAuthRequest;
import com.userid.api.auth.OwnerSocialProviderConfigResponse;
import com.userid.api.client.AuthServerSocialProvider;
import com.userid.api.owner.OwnerResponse;
import com.userid.dal.entity.Owner;
import com.userid.dal.entity.OwnerRole;
import com.userid.dal.entity.OwnerSocialIdentity;
import com.userid.dal.entity.OtpOwner;
import com.userid.dal.entity.OtpType;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
import com.userid.dal.repo.OwnerSocialIdentityRepository;
import com.userid.security.JwtService;
import com.userid.api.client.EmailNormalizer;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.server.ResponseStatusException;

@Service
public class OwnerAuthService {
  private static final String GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
  private static final String GOOGLE_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo";
  private static final String YANDEX_TOKEN_ENDPOINT = "https://oauth.yandex.com/token";
  private static final String YANDEX_USERINFO_ENDPOINT = "https://login.yandex.ru/info?format=json";

  private final OwnerRepository ownerRepository;
  private final OwnerDomainRepository ownerDomainRepository;
  private final OwnerSocialIdentityRepository ownerSocialIdentityRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final EmailService emailService;
  private final OwnerOtpService ownerOtpService;
  private final String verifyBaseUrl;
  private final String resetBaseUrl;
  private final boolean ownerSocialGoogleEnabled;
  private final String ownerSocialGoogleClientId;
  private final String ownerSocialGoogleClientSecret;
  private final String ownerSocialGoogleCallbackUri;
  private final boolean ownerSocialYandexEnabled;
  private final String ownerSocialYandexClientId;
  private final String ownerSocialYandexClientSecret;
  private final String ownerSocialYandexCallbackUri;
  private final boolean ownerSocialVkEnabled;
  private final String ownerSocialVkClientId;
  private final String ownerSocialVkClientSecret;
  private final String ownerSocialVkCallbackUri;
  private final RestClient restClient = RestClient.builder().build();

  public OwnerAuthService(
      OwnerRepository ownerRepository,
      OwnerDomainRepository ownerDomainRepository,
      OwnerSocialIdentityRepository ownerSocialIdentityRepository,
      PasswordEncoder passwordEncoder,
      JwtService jwtService,
      EmailService emailService,
      OwnerOtpService ownerOtpService,
      @Value("${auth.email.verify-base-url}") String verifyBaseUrl,
      @Value("${auth.email.reset-base-url}") String resetBaseUrl,
      @Value("${auth.owner-social.google.enabled:false}") boolean ownerSocialGoogleEnabled,
      @Value("${auth.owner-social.google.client-id:}") String ownerSocialGoogleClientId,
      @Value("${auth.owner-social.google.client-secret:}") String ownerSocialGoogleClientSecret,
      @Value("${auth.owner-social.google.callback-uri:}") String ownerSocialGoogleCallbackUri,
      @Value("${auth.owner-social.yandex.enabled:false}") boolean ownerSocialYandexEnabled,
      @Value("${auth.owner-social.yandex.client-id:}") String ownerSocialYandexClientId,
      @Value("${auth.owner-social.yandex.client-secret:}") String ownerSocialYandexClientSecret,
      @Value("${auth.owner-social.yandex.callback-uri:}") String ownerSocialYandexCallbackUri,
      @Value("${auth.owner-social.vk.enabled:false}") boolean ownerSocialVkEnabled,
      @Value("${auth.owner-social.vk.client-id:}") String ownerSocialVkClientId,
      @Value("${auth.owner-social.vk.client-secret:}") String ownerSocialVkClientSecret,
      @Value("${auth.owner-social.vk.callback-uri:}") String ownerSocialVkCallbackUri
  ) {
    this.ownerRepository = ownerRepository;
    this.ownerDomainRepository = ownerDomainRepository;
    this.ownerSocialIdentityRepository = ownerSocialIdentityRepository;
    this.passwordEncoder = passwordEncoder;
    this.jwtService = jwtService;
    this.emailService = emailService;
    this.ownerOtpService = ownerOtpService;
    this.verifyBaseUrl = verifyBaseUrl;
    this.resetBaseUrl = resetBaseUrl;
    this.ownerSocialGoogleEnabled = ownerSocialGoogleEnabled;
    this.ownerSocialGoogleClientId = ownerSocialGoogleClientId;
    this.ownerSocialGoogleClientSecret = ownerSocialGoogleClientSecret;
    this.ownerSocialGoogleCallbackUri = ownerSocialGoogleCallbackUri;
    this.ownerSocialYandexEnabled = ownerSocialYandexEnabled;
    this.ownerSocialYandexClientId = ownerSocialYandexClientId;
    this.ownerSocialYandexClientSecret = ownerSocialYandexClientSecret;
    this.ownerSocialYandexCallbackUri = ownerSocialYandexCallbackUri;
    this.ownerSocialVkEnabled = ownerSocialVkEnabled;
    this.ownerSocialVkClientId = ownerSocialVkClientId;
    this.ownerSocialVkClientSecret = ownerSocialVkClientSecret;
    this.ownerSocialVkCallbackUri = ownerSocialVkCallbackUri;
  }

  public OwnerLoginResponse login(OwnerLoginRequest request) {
    String email = normalizeEmail(request.email());
    Owner user = ownerRepository.findByEmail(email)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }
    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Email is not confirmed");
    }

    String token = jwtService.generateToken(user);
    return new OwnerLoginResponse(token, toResponse(user));
  }

  @Transactional
  public OwnerLoginResponse socialLogin(OwnerSocialAuthRequest request) {
    return authenticateWithSocial(request, true);
  }

  @Transactional
  public OwnerResponse register(OwnerRegisterRequest request) {
    String email = normalizeEmail(request.email());
    Owner existing = ownerRepository.findByEmail(email).orElse(null);

    if (existing != null) {
      if (existing.isActive()) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
      }
      existing.setPasswordHash(passwordEncoder.encode(request.password()));
      existing.setActive(false);
      existing.setEmailVerifiedAt(null);
      Owner saved = ownerRepository.save(existing);
      ownerOtpService.clearResetCode(saved);
      String code = ownerOtpService.createVerificationCode(saved);
      emailService.sendVerificationEmail(saved.getEmail(), buildVerificationLink(code));
      return toResponse(saved);
    }

    Owner user = Owner.builder()
        .email(email)
        .passwordHash(passwordEncoder.encode(request.password()))
        .role(OwnerRole.USER)
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .active(false)
        .build();

    Owner saved = ownerRepository.save(user);
    String code = ownerOtpService.createVerificationCode(saved);
    emailService.sendVerificationEmail(saved.getEmail(), buildVerificationLink(code));
    return toResponse(saved);
  }

  @Transactional
  public OwnerLoginResponse socialRegister(OwnerSocialAuthRequest request) {
    return authenticateWithSocial(request, true);
  }

  public OwnerSocialProviderConfigResponse getSocialProviderConfig(AuthServerSocialProvider provider) {
    SocialProviderClientConfig config = socialProviderClientConfig(provider);
    return new OwnerSocialProviderConfigResponse(
        provider.pathValue(),
        config.isReady(),
        config.clientId(),
        config.callbackUri());
  }

  @Transactional
  public void confirm(String token) {
    if (token == null || token.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token is required");
    }
    OtpOwner otp = ownerOtpService.requireValid(OtpType.VERIFICATION, token);
    Owner user = otp.getOwner();
    if (!user.isActive()) {
      user.setActive(true);
      user.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
      ownerRepository.save(user);
    }
    ownerOtpService.clearVerificationCode(user);
  }

  @Transactional
  public void requestPasswordReset(OwnerPasswordResetRequest request) {
    String email = normalizeEmail(request.email());
    Owner user = ownerRepository.findByEmail(email)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Email not found"));

    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is not confirmed");
    }
    String code = ownerOtpService.createResetCode(user);
    ownerRepository.save(user);
    emailService.sendPasswordResetEmail(user.getEmail(), buildResetLink(code));
  }

  @Transactional
  public void resetPassword(OwnerPasswordResetConfirmRequest request) {
    OtpOwner otp = ownerOtpService.requireValid(OtpType.RESET, request.token());
    Owner user = otp.getOwner();
    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is not confirmed");
    }
    user.setPasswordHash(passwordEncoder.encode(request.password()));
    ownerRepository.save(user);
    ownerOtpService.clearResetCode(user);
  }

  private OwnerLoginResponse authenticateWithSocial(OwnerSocialAuthRequest request, boolean allowCreate) {
    if (request == null || !StringUtils.hasText(request.provider()) || !StringUtils.hasText(request.code())) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social provider and code are required");
    }

    AuthServerSocialProvider provider = parseProvider(request.provider());
    SocialProviderClientConfig providerConfig = socialProviderClientConfig(provider);
    if (!providerConfig.isReady()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social provider is not configured");
    }

    SocialPrincipal socialPrincipal = resolveSocialPrincipal(provider, providerConfig, request.code().trim());
    OwnerSocialIdentity identity = ownerSocialIdentityRepository
        .findByProviderAndProviderSubject(provider, socialPrincipal.subject())
        .orElse(null);

    Owner owner = identity == null
        ? ownerRepository.findByEmail(normalizeEmail(socialPrincipal.email())).orElse(null)
        : identity.getOwner();
    if (owner == null) {
      if (!allowCreate) {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Owner is not registered");
      }
      owner = Owner.builder()
          .email(socialPrincipal.email())
          .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
          .role(OwnerRole.USER)
          .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
          .active(true)
          .emailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC))
          .build();
    } else if (!owner.isActive()) {
      owner.setActive(true);
      owner.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
    }

    syncOwnerEmail(owner, socialPrincipal.email());
    Owner savedOwner = saveOwner(owner);

    OwnerSocialIdentity socialIdentity = identity == null
        ? OwnerSocialIdentity.builder()
            .owner(savedOwner)
            .provider(provider)
            .providerSubject(socialPrincipal.subject())
            .build()
        : identity;
    socialIdentity.setProviderEmail(socialPrincipal.email());
    socialIdentity.setProviderEmailVerified(socialPrincipal.emailVerified());
    ownerSocialIdentityRepository.save(socialIdentity);

    return new OwnerLoginResponse(jwtService.generateToken(savedOwner), toResponse(savedOwner));
  }

  private void syncOwnerEmail(Owner owner, String email) {
    String normalizedEmail = normalizeEmail(email);
    if (!StringUtils.hasText(normalizedEmail) || normalizedEmail.equals(normalizeEmail(owner.getEmail()))) {
      return;
    }
    boolean existsForAnotherOwner = ownerRepository.findByEmail(normalizedEmail)
        .filter(existing -> !existing.getId().equals(owner.getId()))
        .isPresent();
    if (!existsForAnotherOwner) {
      owner.setEmail(normalizedEmail);
    }
  }

  private Owner saveOwner(Owner owner) {
    try {
      return ownerRepository.save(owner);
    } catch (DataIntegrityViolationException ex) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
    }
  }

  private AuthServerSocialProvider parseProvider(String provider) {
    try {
      return AuthServerSocialProvider.fromPath(provider);
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage());
    }
  }

  private SocialPrincipal resolveSocialPrincipal(
      AuthServerSocialProvider provider,
      SocialProviderClientConfig providerConfig,
      String code
  ) {
    return switch (provider) {
      case GOOGLE -> resolveGooglePrincipal(providerConfig, code);
      case YANDEX -> resolveYandexPrincipal(providerConfig, code);
      case VK -> resolveVkPrincipal(providerConfig, code);
    };
  }

  private SocialPrincipal resolveGooglePrincipal(SocialProviderClientConfig providerConfig, String code) {
    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("code", code);
    form.add("client_id", providerConfig.clientId());
    form.add("client_secret", providerConfig.clientSecret());
    form.add("redirect_uri", providerConfig.callbackUri());
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

  private SocialPrincipal resolveYandexPrincipal(SocialProviderClientConfig providerConfig, String code) {
    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "authorization_code");
    form.add("code", code);
    form.add("client_id", providerConfig.clientId());
    form.add("client_secret", providerConfig.clientSecret());
    form.add("redirect_uri", providerConfig.callbackUri());

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
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Yandex OAuth client config is invalid");
      }
      throw new ResponseStatusException(
          HttpStatus.UNAUTHORIZED,
          "Invalid Yandex authorization code or redirect_uri mismatch");
    } catch (RestClientException ex) {
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

  private SocialPrincipal resolveVkPrincipal(SocialProviderClientConfig providerConfig, String code) {
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    params.add("client_id", providerConfig.clientId());
    params.add("client_secret", providerConfig.clientSecret());
    params.add("redirect_uri", providerConfig.callbackUri());
    params.add("code", code);

    VkTokenResponse tokenResponse;
    try {
      tokenResponse = restClient.get()
          .uri(uriBuilder -> uriBuilder
              .scheme("https")
              .host("oauth.vk.com")
              .path("/access_token")
              .queryParams(params)
              .build())
          .retrieve()
          .body(VkTokenResponse.class);
    } catch (RestClientException ex) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid VK authorization code");
    }

    if (tokenResponse == null
        || !StringUtils.hasText(tokenResponse.accessToken())
        || tokenResponse.userId() == null) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "VK token response is invalid");
    }

    String email = normalizeEmail(tokenResponse.email());
    if (!StringUtils.hasText(email)) {
      throw new ResponseStatusException(
          HttpStatus.UNAUTHORIZED,
          "VK email is unavailable. Add email scope in VK app settings");
    }

    return new SocialPrincipal(String.valueOf(tokenResponse.userId()), email, true);
  }

  private SocialProviderClientConfig socialProviderClientConfig(AuthServerSocialProvider provider) {
    return switch (provider) {
      case GOOGLE -> new SocialProviderClientConfig(
          ownerSocialGoogleEnabled,
          trimToNull(ownerSocialGoogleClientId),
          trimToNull(ownerSocialGoogleClientSecret),
          trimToNull(ownerSocialGoogleCallbackUri));
      case YANDEX -> new SocialProviderClientConfig(
          ownerSocialYandexEnabled,
          trimToNull(ownerSocialYandexClientId),
          trimToNull(ownerSocialYandexClientSecret),
          trimToNull(ownerSocialYandexCallbackUri));
      case VK -> new SocialProviderClientConfig(
          ownerSocialVkEnabled,
          trimToNull(ownerSocialVkClientId),
          trimToNull(ownerSocialVkClientSecret),
          trimToNull(ownerSocialVkCallbackUri));
    };
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

  private OwnerResponse toResponse(Owner user) {
    List<Long> domainIds;
    if (user.getRole() == OwnerRole.ADMIN) {
      domainIds = Collections.emptyList();
    } else {
      domainIds = ownerDomainRepository.findByOwnerId(user.getId()).stream()
          .map(link -> link.getDomain().getId())
          .distinct()
          .toList();
    }

    return new OwnerResponse(
        user.getId(),
        user.getEmail(),
        user.getRole(),
        user.getCreatedAt(),
        domainIds
    );
  }

  private String buildVerificationLink(String token) {
    if (verifyBaseUrl.contains("?")) {
      return verifyBaseUrl + "&token=" + token;
    }
    return verifyBaseUrl + "?token=" + token;
  }

  private String buildResetLink(String token) {
    if (resetBaseUrl.contains("?")) {
      return resetBaseUrl + "&token=" + token;
    }
    return resetBaseUrl + "?token=" + token;
  }

  private record SocialProviderClientConfig(
      boolean enabled,
      String clientId,
      String clientSecret,
      String callbackUri
  ) {
    boolean isReady() {
      return enabled
          && StringUtils.hasText(clientId)
          && StringUtils.hasText(clientSecret)
          && StringUtils.hasText(callbackUri);
    }
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

}
