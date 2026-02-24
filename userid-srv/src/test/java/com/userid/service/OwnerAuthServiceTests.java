package com.userid.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.userid.api.auth.OwnerLoginRequestDTO;
import com.userid.api.auth.OwnerRegisterRequestDTO;
import com.userid.api.client.SocialProviderOAuthClient;
import com.userid.api.owner.OwnerResponseDTO;
import com.userid.dal.entity.OwnerEntity;
import com.userid.dal.entity.OwnerRoleEnum;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
import com.userid.dal.repo.OwnerSocialIdentityRepository;
import com.userid.security.JwtService;
import java.time.OffsetDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class OwnerAuthServiceTests {
  @Mock
  private OwnerRepository ownerRepository;
  @Mock
  private OwnerDomainRepository ownerDomainRepository;
  @Mock
  private OwnerSocialIdentityRepository ownerSocialIdentityRepository;
  @Mock
  private PasswordEncoder passwordEncoder;
  @Mock
  private JwtService jwtService;
  @Mock
  private EmailService emailService;
  @Mock
  private OwnerOtpService ownerOtpService;
  @Mock
  private SocialProviderOAuthClient socialProviderOAuthClient;

  private OwnerAuthService ownerAuthService;

  @BeforeEach
  void setUp() {
    ownerAuthService = new OwnerAuthService(
        ownerRepository,
        ownerDomainRepository,
        ownerSocialIdentityRepository,
        passwordEncoder,
        jwtService,
        emailService,
        ownerOtpService,
        "https://identio.ru/app/verify",
        "https://identio.ru/app/reset",
        false,
        "",
        "",
        "",
        false,
        "",
        "",
        "",
        false,
        "",
        "",
        "",
        socialProviderOAuthClient);
  }

  @Test
  void loginWhenOwnerEmailNotConfirmedResendsVerificationAndReturnsUnauthorized() {
    OwnerEntity owner = OwnerEntity.builder()
        .id(7L)
        .email("owner@identio.ru")
        .passwordHash("hash")
        .role(OwnerRoleEnum.USER)
        .createdAt(OffsetDateTime.now())
        .active(false)
        .build();

    when(ownerRepository.findByEmail("owner@identio.ru")).thenReturn(Optional.of(owner));
    when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
    when(ownerOtpService.reuseVerificationCode(owner)).thenReturn("verify-code");

    assertThatThrownBy(() -> ownerAuthService.login(new OwnerLoginRequestDTO("owner@identio.ru", "secret")))
        .isInstanceOfSatisfying(
            ResponseStatusException.class,
            ex -> {
              assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
              assertThat(ex.getReason()).isEqualTo("Invalid credentials");
            });

    verify(ownerOtpService).reuseVerificationCode(owner);
    verify(emailService).sendVerificationEmail(
        "owner@identio.ru",
        "https://identio.ru/app/verify?token=verify-code");
    verify(jwtService, never()).generateToken(owner);
  }

  @Test
  void registerWhenOwnerExistsAndUnconfirmedOverridesPasswordAndResendsActivationEmail() {
    OwnerEntity existing = OwnerEntity.builder()
        .id(11L)
        .email("owner@identio.ru")
        .passwordHash("old-hash")
        .role(OwnerRoleEnum.USER)
        .createdAt(OffsetDateTime.now())
        .active(false)
        .emailVerifiedAt(OffsetDateTime.now())
        .build();

    when(ownerRepository.findByEmail("owner@identio.ru")).thenReturn(Optional.of(existing));
    when(passwordEncoder.encode("new-secret")).thenReturn("new-hash");
    when(ownerRepository.save(existing)).thenReturn(existing);
    when(ownerOtpService.reuseVerificationCode(existing)).thenReturn("verify-code");
    when(ownerDomainRepository.findByOwnerId(11L)).thenReturn(java.util.List.of());

    OwnerResponseDTO response = ownerAuthService.register(new OwnerRegisterRequestDTO("owner@identio.ru", "new-secret"));

    assertThat(response.id()).isEqualTo(11L);
    assertThat(existing.getPasswordHash()).isEqualTo("new-hash");
    assertThat(existing.isActive()).isFalse();
    assertThat(existing.getEmailVerifiedAt()).isNull();
    verify(ownerOtpService).clearResetCode(existing);
    verify(ownerOtpService).reuseVerificationCode(existing);
    verify(emailService).sendVerificationEmail(
        "owner@identio.ru",
        "https://identio.ru/app/verify?token=verify-code");
  }

  @Test
  void registerWhenOwnerExistsAndActiveAndPasswordMatchesReturnsSuccess() {
    OwnerEntity existing = OwnerEntity.builder()
        .id(12L)
        .email("owner@identio.ru")
        .passwordHash("hash")
        .role(OwnerRoleEnum.USER)
        .createdAt(OffsetDateTime.now())
        .active(true)
        .emailVerifiedAt(OffsetDateTime.now())
        .build();

    when(ownerRepository.findByEmail("owner@identio.ru")).thenReturn(Optional.of(existing));
    when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
    when(ownerDomainRepository.findByOwnerId(12L)).thenReturn(java.util.List.of());

    OwnerResponseDTO response = ownerAuthService.register(new OwnerRegisterRequestDTO("owner@identio.ru", "secret"));

    assertThat(response.id()).isEqualTo(12L);
    verify(ownerOtpService, never()).createResetCode(existing);
    verify(emailService, never()).sendPasswordResetEmail("owner@identio.ru", "https://identio.ru/app/reset?token=reset-code");
  }

  @Test
  void registerWhenOwnerExistsAndActiveAndPasswordMismatchSendsResetEmailAndReturnsSuccess() {
    OwnerEntity existing = OwnerEntity.builder()
        .id(13L)
        .email("owner@identio.ru")
        .passwordHash("hash")
        .role(OwnerRoleEnum.USER)
        .createdAt(OffsetDateTime.now())
        .active(true)
        .emailVerifiedAt(OffsetDateTime.now())
        .build();

    when(ownerRepository.findByEmail("owner@identio.ru")).thenReturn(Optional.of(existing));
    when(passwordEncoder.matches("secret", "hash")).thenReturn(false);
    when(ownerOtpService.createResetCode(existing)).thenReturn("reset-code");
    when(ownerRepository.save(existing)).thenReturn(existing);
    when(ownerDomainRepository.findByOwnerId(13L)).thenReturn(java.util.List.of());

    OwnerResponseDTO response = ownerAuthService.register(new OwnerRegisterRequestDTO("owner@identio.ru", "secret"));

    assertThat(response.id()).isEqualTo(13L);
    verify(ownerOtpService).createResetCode(existing);
    verify(ownerRepository).save(existing);
    verify(emailService).sendPasswordResetEmail(
        "owner@identio.ru",
        "https://identio.ru/app/reset?token=reset-code");
  }
}
