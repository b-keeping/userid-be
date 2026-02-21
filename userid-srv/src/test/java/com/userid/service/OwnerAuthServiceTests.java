package com.userid.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.userid.api.auth.OwnerLoginRequest;
import com.userid.api.auth.OwnerRegisterRequest;
import com.userid.api.owner.OwnerResponse;
import com.userid.dal.entity.Owner;
import com.userid.dal.entity.OwnerRole;
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
        "");
  }

  @Test
  void loginWhenOwnerEmailNotConfirmedResendsVerificationAndReturnsUnauthorized() {
    Owner owner = Owner.builder()
        .id(7L)
        .email("owner@identio.ru")
        .passwordHash("hash")
        .role(OwnerRole.USER)
        .createdAt(OffsetDateTime.now())
        .active(false)
        .build();

    when(ownerRepository.findByEmail("owner@identio.ru")).thenReturn(Optional.of(owner));
    when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
    when(ownerOtpService.createVerificationCode(owner)).thenReturn("verify-code");

    assertThatThrownBy(() -> ownerAuthService.login(new OwnerLoginRequest("owner@identio.ru", "secret")))
        .isInstanceOfSatisfying(
            ResponseStatusException.class,
            ex -> {
              assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
              assertThat(ex.getReason()).isEqualTo("Invalid credentials");
            });

    verify(ownerOtpService).createVerificationCode(owner);
    verify(emailService).sendVerificationEmail(
        "owner@identio.ru",
        "https://identio.ru/app/verify?token=verify-code");
    verify(jwtService, never()).generateToken(owner);
  }

  @Test
  void registerWhenOwnerExistsAndUnconfirmedOverridesPasswordAndResendsActivationEmail() {
    Owner existing = Owner.builder()
        .id(11L)
        .email("owner@identio.ru")
        .passwordHash("old-hash")
        .role(OwnerRole.USER)
        .createdAt(OffsetDateTime.now())
        .active(false)
        .emailVerifiedAt(OffsetDateTime.now())
        .build();

    when(ownerRepository.findByEmail("owner@identio.ru")).thenReturn(Optional.of(existing));
    when(passwordEncoder.encode("new-secret")).thenReturn("new-hash");
    when(ownerRepository.save(existing)).thenReturn(existing);
    when(ownerOtpService.createVerificationCode(existing)).thenReturn("verify-code");
    when(ownerDomainRepository.findByOwnerId(11L)).thenReturn(java.util.List.of());

    OwnerResponse response = ownerAuthService.register(new OwnerRegisterRequest("owner@identio.ru", "new-secret"));

    assertThat(response.id()).isEqualTo(11L);
    assertThat(existing.getPasswordHash()).isEqualTo("new-hash");
    assertThat(existing.isActive()).isFalse();
    assertThat(existing.getEmailVerifiedAt()).isNull();
    verify(ownerOtpService).clearResetCode(existing);
    verify(ownerOtpService).createVerificationCode(existing);
    verify(emailService).sendVerificationEmail(
        "owner@identio.ru",
        "https://identio.ru/app/verify?token=verify-code");
  }
}
