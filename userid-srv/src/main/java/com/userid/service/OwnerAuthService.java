package com.userid.service;

import com.userid.api.auth.OwnerLoginRequestDTO;
import com.userid.api.auth.OwnerLoginResponseDTO;
import com.userid.api.auth.OwnerPasswordResetConfirmRequestDTO;
import com.userid.api.auth.OwnerPasswordResetRequestDTO;
import com.userid.api.auth.OwnerRegisterRequestDTO;
import com.userid.api.auth.OwnerSocialAuthRequestDTO;
import com.userid.api.auth.OwnerSocialProviderConfigResponseDTO;
import com.userid.api.client.AuthServerSocialLoginRequestDTO;
import com.userid.api.client.AuthServerSocialProviderEnum;
import com.userid.api.owner.OwnerResponseDTO;
import com.userid.api.client.SocialProviderOAuthClient;
import com.userid.dal.entity.OwnerEntity;
import com.userid.dal.entity.OwnerRoleEnum;
import com.userid.dal.entity.OwnerSocialIdentityEntity;
import com.userid.dal.entity.OtpOwnerEntity;
import com.userid.dal.entity.OtpTypeEnum;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

@Service
public class OwnerAuthService {
  private static final Logger log = LoggerFactory.getLogger(OwnerAuthService.class);

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
  private final SocialProviderOAuthClient socialProviderOAuthClient;

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
      @Value("${auth.owner-social.vk.callback-uri:}") String ownerSocialVkCallbackUri,
      SocialProviderOAuthClient socialProviderOAuthClient
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
    this.socialProviderOAuthClient = socialProviderOAuthClient;
  }

  public OwnerLoginResponseDTO login(OwnerLoginRequestDTO request) {
    String email = normalizeEmail(request.email());
    OwnerEntity user = ownerRepository.findByEmail(email)
        .orElseThrow(this::invalidCredentials);

    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
      throw invalidCredentials();
    }
    if (!user.isActive()) {
      resendVerificationEmailBestEffort(user);
      throw invalidCredentials();
    }

    String token = jwtService.generateToken(user);
    return new OwnerLoginResponseDTO(token, toResponse(user));
  }

  @Transactional
  public OwnerLoginResponseDTO socialLogin(OwnerSocialAuthRequestDTO request) {
    return authenticateWithSocial(request, true);
  }

  @Transactional
  public OwnerResponseDTO register(OwnerRegisterRequestDTO request) {
    String email = normalizeEmail(request.email());
    OwnerEntity existing = ownerRepository.findByEmail(email).orElse(null);

    if (existing != null) {
      if (existing.isActive()) {
        if (passwordEncoder.matches(request.password(), existing.getPasswordHash())) {
          return toResponse(existing);
        }
        sendOwnerPasswordResetBestEffort(existing);
        return toResponse(existing);
      }
      existing.setPasswordHash(passwordEncoder.encode(request.password()));
      existing.setActive(false);
      existing.setEmailVerifiedAt(null);
      OwnerEntity saved = ownerRepository.save(existing);
      ownerOtpService.clearResetCode(saved);
      String code = ownerOtpService.reuseVerificationCode(saved);
      emailService.sendVerificationEmail(saved.getEmail(), buildVerificationLink(code));
      return toResponse(saved);
    }

    OwnerEntity user = OwnerEntity.builder()
        .email(email)
        .passwordHash(passwordEncoder.encode(request.password()))
        .role(OwnerRoleEnum.USER)
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .active(false)
        .build();

    OwnerEntity saved = ownerRepository.save(user);
    String code = ownerOtpService.createVerificationCode(saved);
    emailService.sendVerificationEmail(saved.getEmail(), buildVerificationLink(code));
    return toResponse(saved);
  }

  @Transactional
  public OwnerLoginResponseDTO socialRegister(OwnerSocialAuthRequestDTO request) {
    return authenticateWithSocial(request, true);
  }

  public OwnerSocialProviderConfigResponseDTO getSocialProviderConfig(AuthServerSocialProviderEnum provider) {
    SocialProviderClientConfigDTO config = socialProviderClientConfig(provider);
    return new OwnerSocialProviderConfigResponseDTO(
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
    OtpOwnerEntity otp = ownerOtpService.requireValid(OtpTypeEnum.VERIFICATION, token);
    OwnerEntity user = otp.getOwner();
    if (!user.isActive()) {
      user.setActive(true);
      user.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
      ownerRepository.save(user);
    }
    ownerOtpService.clearVerificationCode(user);
  }

  @Transactional
  public void requestPasswordReset(OwnerPasswordResetRequestDTO request) {
    String email = normalizeEmail(request.email());
    OwnerEntity user = ownerRepository.findByEmail(email)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Email not found"));

    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is not confirmed");
    }
    String code = ownerOtpService.createResetCode(user);
    ownerRepository.save(user);
    emailService.sendPasswordResetEmail(user.getEmail(), buildResetLink(code));
  }

  @Transactional
  public void resetPassword(OwnerPasswordResetConfirmRequestDTO request) {
    OtpOwnerEntity otp = ownerOtpService.requireValid(OtpTypeEnum.RESET, request.token());
    OwnerEntity user = otp.getOwner();
    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is not confirmed");
    }
    user.setPasswordHash(passwordEncoder.encode(request.password()));
    ownerRepository.save(user);
    ownerOtpService.clearResetCode(user);
  }

  private OwnerLoginResponseDTO authenticateWithSocial(OwnerSocialAuthRequestDTO request, boolean allowCreate) {
    if (request == null || !StringUtils.hasText(request.provider()) || !StringUtils.hasText(request.code())) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social provider and code are required");
    }

    AuthServerSocialProviderEnum provider = parseProvider(request.provider());
    SocialProviderClientConfigDTO providerConfig = socialProviderClientConfig(provider);
    if (!providerConfig.isReady()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social provider is not configured");
    }

    SocialProviderOAuthClient.SocialPrincipalDTO socialPrincipal = socialProviderOAuthClient.resolvePrincipal(
        provider,
        new SocialProviderOAuthClient.SocialProviderAuthConfigDTO(
            providerConfig.clientId(),
            providerConfig.clientSecret(),
            providerConfig.callbackUri()),
        new AuthServerSocialLoginRequestDTO(
            request.code(),
            request.codeVerifier(),
            request.deviceId(),
            request.state()));
    OwnerSocialIdentityEntity identity = ownerSocialIdentityRepository
        .findByProviderAndProviderSubject(provider, socialPrincipal.subject())
        .orElse(null);

    OwnerEntity owner = identity == null
        ? ownerRepository.findByEmail(normalizeEmail(socialPrincipal.email())).orElse(null)
        : identity.getOwner();
    if (owner == null) {
      if (!allowCreate) {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Owner is not registered");
      }
      owner = OwnerEntity.builder()
          .email(socialPrincipal.email())
          .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
          .role(OwnerRoleEnum.USER)
          .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
          .active(true)
          .emailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC))
          .build();
    } else if (!owner.isActive()) {
      owner.setActive(true);
      owner.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
    }

    syncOwnerEmail(owner, socialPrincipal.email());
    OwnerEntity savedOwner = saveOwner(owner);

    OwnerSocialIdentityEntity socialIdentity = identity == null
        ? OwnerSocialIdentityEntity.builder()
            .owner(savedOwner)
            .provider(provider)
            .providerSubject(socialPrincipal.subject())
            .build()
        : identity;
    socialIdentity.setProviderEmail(socialPrincipal.email());
    socialIdentity.setProviderEmailVerified(socialPrincipal.emailVerified());
    ownerSocialIdentityRepository.save(socialIdentity);

    return new OwnerLoginResponseDTO(jwtService.generateToken(savedOwner), toResponse(savedOwner));
  }

  private void syncOwnerEmail(OwnerEntity owner, String email) {
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

  private OwnerEntity saveOwner(OwnerEntity owner) {
    try {
      return ownerRepository.save(owner);
    } catch (DataIntegrityViolationException ex) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
    }
  }

  private AuthServerSocialProviderEnum parseProvider(String provider) {
    try {
      return AuthServerSocialProviderEnum.fromPath(provider);
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage());
    }
  }

  private SocialProviderClientConfigDTO socialProviderClientConfig(AuthServerSocialProviderEnum provider) {
    return switch (provider) {
      case GOOGLE -> new SocialProviderClientConfigDTO(
          ownerSocialGoogleEnabled,
          trimToNull(ownerSocialGoogleClientId),
          trimToNull(ownerSocialGoogleClientSecret),
          trimToNull(ownerSocialGoogleCallbackUri));
      case YANDEX -> new SocialProviderClientConfigDTO(
          ownerSocialYandexEnabled,
          trimToNull(ownerSocialYandexClientId),
          trimToNull(ownerSocialYandexClientSecret),
          trimToNull(ownerSocialYandexCallbackUri));
      case VK -> new SocialProviderClientConfigDTO(
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

  private ResponseStatusException invalidCredentials() {
    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
  }

  private void resendVerificationEmailBestEffort(OwnerEntity owner) {
    try {
      String code = ownerOtpService.reuseVerificationCode(owner);
      emailService.sendVerificationEmail(owner.getEmail(), buildVerificationLink(code));
    } catch (Exception ex) {
      log.warn(
          "Owner verification resend failed ownerId={} email={} reason={}",
          owner.getId(),
          owner.getEmail(),
          ex.getMessage());
    }
  }

  private void sendOwnerPasswordResetBestEffort(OwnerEntity owner) {
    try {
      String code = ownerOtpService.createResetCode(owner);
      ownerRepository.save(owner);
      emailService.sendPasswordResetEmail(owner.getEmail(), buildResetLink(code));
    } catch (Exception ex) {
      log.warn(
          "Owner password reset send failed ownerId={} email={} reason={}",
          owner.getId(),
          owner.getEmail(),
          ex.getMessage());
    }
  }

  private OwnerResponseDTO toResponse(OwnerEntity user) {
    List<Long> domainIds;
    if (user.getRole() == OwnerRoleEnum.ADMIN) {
      domainIds = Collections.emptyList();
    } else {
      domainIds = ownerDomainRepository.findByOwnerId(user.getId()).stream()
          .map(link -> link.getDomain().getId())
          .distinct()
          .toList();
    }

    return new OwnerResponseDTO(
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

  private record SocialProviderClientConfigDTO(
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
}
