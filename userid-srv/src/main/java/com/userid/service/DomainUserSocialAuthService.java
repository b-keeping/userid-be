package com.userid.service;

import com.userid.api.client.AuthServerSocialLoginRequestDTO;
import com.userid.api.client.AuthServerSocialProviderEnum;
import com.userid.api.client.SocialProviderOAuthClient;
import com.userid.api.user.UserAuthResponseDTO;
import com.userid.api.user.UserLoginResponseDTO;
import com.userid.dal.entity.DomainEntity;
import com.userid.dal.entity.DomainSocialProviderConfigEntity;
import com.userid.dal.entity.UserEntity;
import com.userid.dal.entity.UserSocialIdentityEntity;
import com.userid.dal.repo.DomainSocialProviderConfigRepository;
import com.userid.dal.repo.ProfileFieldRepository;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class DomainUserSocialAuthService {
  private final DomainSocialProviderConfigRepository domainSocialProviderConfigRepository;
  private final ProfileFieldRepository profileFieldRepository;
  private final UserSocialIdentityRepository userSocialIdentityRepository;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final DomainUserJwtService domainUserJwtService;
  private final SocialProviderOAuthClient socialProviderOAuthClient;

  public UserLoginResponseDTO login(
      Long domainId,
      AuthServerSocialProviderEnum provider,
      AuthServerSocialLoginRequestDTO request
  ) {
    String code = request == null ? null : request.code();
    if (!StringUtils.hasText(code)) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social auth code is required");
    }

    DomainSocialProviderConfigEntity config = domainSocialProviderConfigRepository
        .findByDomainIdAndProvider(domainId, provider)
        .orElseThrow(() -> new ResponseStatusException(
            HttpStatus.BAD_REQUEST,
            "Social provider is not configured for this domain"));
    if (!Boolean.TRUE.equals(config.getEnabled())) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social provider is disabled for this domain");
    }
    boolean profileCompletionRequired = profileFieldRepository.existsByDomainId(domainId);

    SocialProviderOAuthClient.SocialPrincipalDTO socialPrincipal = socialProviderOAuthClient.resolvePrincipal(
        provider,
        new SocialProviderOAuthClient.SocialProviderAuthConfigDTO(
            config.getClientId(),
            config.getClientSecret(),
            config.getCallbackUri()),
        request);

    log.info(
        "Social login resolved principal domainId={} provider={} subject={} email={}",
        domainId,
        provider.pathValue(),
        socialPrincipal.subject(),
        socialPrincipal.email());

    UserSocialIdentityEntity identity = userSocialIdentityRepository
        .findByDomainIdAndProviderAndProviderSubject(domainId, provider, socialPrincipal.subject())
        .orElse(null);
    UserEntity user = identity == null
        ? resolveOrCreateUser(config.getDomain(), socialPrincipal, profileCompletionRequired)
        : identity.getUser();
    boolean userChanged = syncUserFromSocial(user, socialPrincipal, profileCompletionRequired);
    if (userChanged) {
      user = saveUser(user);
    }

    UserSocialIdentityEntity linkedIdentity = identity == null
        ? createIdentity(user, config.getDomain(), provider, socialPrincipal)
        : identity;
    updateIdentity(linkedIdentity, socialPrincipal);
    userSocialIdentityRepository.save(linkedIdentity);

    String token = domainUserJwtService.generateToken(user);
    return new UserLoginResponseDTO(token, toAuthResponse(user));
  }

  private UserEntity resolveOrCreateUser(
      DomainEntity domain,
      SocialProviderOAuthClient.SocialPrincipalDTO socialPrincipal,
      boolean profileCompletionRequired
  ) {
    return userRepository.findByDomainIdAndEmail(domain.getId(), socialPrincipal.email())
        .or(() -> userRepository.findByDomainIdAndEmailPending(domain.getId(), socialPrincipal.email()))
        .orElseGet(() -> saveUser(UserEntity.builder()
            .domain(domain)
            .email(socialPrincipal.email())
            .emailPending(socialPrincipal.email())
            .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
            .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
            .emailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC))
            .active(!profileCompletionRequired)
            .build()));
  }

  private UserEntity saveUser(UserEntity user) {
    try {
      return userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered");
    }
  }

  private boolean syncUserFromSocial(
      UserEntity user,
      SocialProviderOAuthClient.SocialPrincipalDTO socialPrincipal,
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

  private UserSocialIdentityEntity createIdentity(
      UserEntity user,
      DomainEntity domain,
      AuthServerSocialProviderEnum provider,
      SocialProviderOAuthClient.SocialPrincipalDTO socialPrincipal
  ) {
    return UserSocialIdentityEntity.builder()
        .user(user)
        .domain(domain)
        .provider(provider)
        .providerSubject(socialPrincipal.subject())
        .providerEmail(socialPrincipal.email())
        .providerEmailVerified(socialPrincipal.emailVerified())
        .build();
  }

  private void updateIdentity(
      UserSocialIdentityEntity identity,
      SocialProviderOAuthClient.SocialPrincipalDTO socialPrincipal
  ) {
    identity.setProviderEmail(socialPrincipal.email());
    identity.setProviderEmailVerified(socialPrincipal.emailVerified());
  }

  private UserAuthResponseDTO toAuthResponse(UserEntity user) {
    return new UserAuthResponseDTO(
        user.getId(),
        user.getDomain().getId(),
        user.getEmail(),
        user.getEmailVerifiedAt() != null,
        user.isActive(),
        user.getCreatedAt());
  }
}
