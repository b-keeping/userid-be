package com.userid.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.userid.api.common.ApiMessageDTO;
import com.userid.api.user.UserConfirmRequestDTO;
import com.userid.api.user.UserForgotPasswordRequestDTO;
import com.userid.api.user.UserLoginResponseDTO;
import com.userid.api.user.UserRegistrationRequestDTO;
import com.userid.dal.entity.DomainEntity;
import com.userid.dal.entity.OtpTypeEnum;
import com.userid.dal.entity.OtpUserEntity;
import com.userid.dal.entity.UserEntity;
import com.userid.dal.repo.UserRepository;
import com.userid.security.DomainUserJwtService;
import java.time.OffsetDateTime;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class DomainUserAuthServiceTests {
  @Mock
  private UserRepository userRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private DomainUserJwtService domainUserJwtService;

  @Mock
  private UserOtpService userOtpService;

  @Mock
  private EmailService emailService;

  @Mock
  private UserService userService;

  @InjectMocks
  private DomainUserAuthService domainUserAuthService;

  @Test
  void confirmByCodeMarksEmailAsVerified() {
    DomainEntity domain = DomainEntity.builder().id(7L).name("example.org").build();
    UserEntity user = UserEntity.builder()
        .domain(domain)
        .emailPending("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .build();
    OtpUserEntity otp = OtpUserEntity.builder().user(user).type(OtpTypeEnum.VERIFICATION).code("abc123").build();

    when(userOtpService.requireValid(OtpTypeEnum.VERIFICATION, "abc123")).thenReturn(otp);
    when(domainUserJwtService.generateToken(user)).thenReturn("jwt-token");

    UserLoginResponseDTO response = domainUserAuthService.confirm(7L, new UserConfirmRequestDTO("abc123"));

    assertThat(response.token()).isEqualTo("jwt-token");
    assertThat(response.user()).isNotNull();
    assertThat(response.user().confirmed()).isTrue();
    assertThat(response.user().active()).isTrue();
    assertThat(user.getEmail()).isEqualTo("user@example.org");
    assertThat(user.getEmailVerifiedAt()).isNotNull();
    verify(domainUserJwtService).generateToken(user);
    verify(userOtpService).clearVerificationCode(user);
    verify(userRepository).saveAndFlush(user);
  }

  @Test
  void confirmByCodeRejectsDomainMismatch() {
    DomainEntity domain = DomainEntity.builder().id(7L).name("example.org").build();
    UserEntity user = UserEntity.builder()
        .domain(domain)
        .emailPending("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .build();
    OtpUserEntity otp = OtpUserEntity.builder().user(user).type(OtpTypeEnum.VERIFICATION).code("abc123").build();

    when(userOtpService.requireValid(OtpTypeEnum.VERIFICATION, "abc123")).thenReturn(otp);

    assertThatThrownBy(() -> domainUserAuthService.confirm(99L, new UserConfirmRequestDTO("abc123")))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining(HttpStatus.FORBIDDEN.toString());
  }

  @Test
  void forgotPasswordWhenEmailNotConfirmedResendsVerificationAndReturnsOk() {
    DomainEntity domain = DomainEntity.builder().id(7L).name("example.org").build();
    UserEntity user = UserEntity.builder()
        .domain(domain)
        .email("user@example.org")
        .emailPending("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .emailVerifiedAt(null)
        .build();
    when(userRepository.findByDomainIdAndEmail(7L, "user@example.org")).thenReturn(java.util.Optional.of(user));
    when(userOtpService.createVerificationCode(user)).thenReturn("verify-code");

    ApiMessageDTO response = domainUserAuthService.forgotPassword(7L, new UserForgotPasswordRequestDTO("user@example.org"));

    assertThat(response.message()).isEqualTo("ok");
    verify(userOtpService).createVerificationCode(user);
    verify(emailService).sendOtpEmail(domain, "user@example.org", "verify-code");
    verify(userOtpService, never()).createResetCode(user);
    verify(emailService, never()).sendUserPasswordResetCode(domain, "user@example.org", "verify-code");
    verify(userRepository, never()).save(user);
  }

  @Test
  void forgotPasswordWhenEmailConfirmedSendsResetCode() {
    DomainEntity domain = DomainEntity.builder().id(7L).name("example.org").build();
    UserEntity user = UserEntity.builder()
        .domain(domain)
        .email("user@example.org")
        .emailPending("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .emailVerifiedAt(OffsetDateTime.now())
        .build();
    when(userRepository.findByDomainIdAndEmail(7L, "user@example.org")).thenReturn(java.util.Optional.of(user));
    when(userOtpService.createResetCode(user)).thenReturn("reset-code");

    ApiMessageDTO response = domainUserAuthService.forgotPassword(7L, new UserForgotPasswordRequestDTO("user@example.org"));

    assertThat(response.message()).isEqualTo("ok");
    verify(userOtpService).createResetCode(user);
    verify(userRepository).save(user);
    verify(emailService).sendUserPasswordResetCode(domain, "user@example.org", "reset-code");
    verify(userOtpService, never()).createVerificationCode(user);
  }

  @Test
  void registerWhenExistingActiveAndPasswordMatchesReturnsLogin() {
    DomainEntity domain = DomainEntity.builder().id(7L).name("example.org").build();
    UserEntity user = UserEntity.builder()
        .id(10L)
        .domain(domain)
        .email("user@example.org")
        .emailPending("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .emailVerifiedAt(OffsetDateTime.now())
        .active(true)
        .build();
    UserRegistrationRequestDTO request = new UserRegistrationRequestDTO("user@example.org", "secret", java.util.List.of());

    when(userService.registerByDomain(7L, request))
        .thenThrow(new ResponseStatusException(HttpStatus.CONFLICT, "User already registered"));
    when(userRepository.findByDomainIdAndEmail(7L, "user@example.org")).thenReturn(java.util.Optional.of(user));
    when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
    when(domainUserJwtService.generateToken(user)).thenReturn("jwt-token");

    UserLoginResponseDTO response = domainUserAuthService.register(7L, request);

    assertThat(response.token()).isEqualTo("jwt-token");
    assertThat(response.user()).isNotNull();
    verify(userOtpService, never()).createResetCode(user);
    verify(emailService, never()).sendUserPasswordResetCode(domain, "user@example.org", "reset-code");
  }

  @Test
  void registerWhenExistingActiveAndPasswordMismatchSendsResetAndReturnsNoToken() {
    DomainEntity domain = DomainEntity.builder().id(7L).name("example.org").build();
    UserEntity user = UserEntity.builder()
        .id(10L)
        .domain(domain)
        .email("user@example.org")
        .emailPending("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .emailVerifiedAt(OffsetDateTime.now())
        .active(true)
        .build();
    UserRegistrationRequestDTO request = new UserRegistrationRequestDTO("user@example.org", "secret", java.util.List.of());

    when(userService.registerByDomain(7L, request))
        .thenThrow(new ResponseStatusException(HttpStatus.CONFLICT, "User already registered"));
    when(userRepository.findByDomainIdAndEmail(7L, "user@example.org")).thenReturn(java.util.Optional.of(user));
    when(passwordEncoder.matches("secret", "hash")).thenReturn(false);
    when(userOtpService.createResetCode(user)).thenReturn("reset-code");

    UserLoginResponseDTO response = domainUserAuthService.register(7L, request);

    assertThat(response.token()).isNull();
    assertThat(response.user()).isNotNull();
    verify(userOtpService).createResetCode(user);
    verify(userRepository).save(user);
    verify(emailService).sendUserPasswordResetCode(domain, "user@example.org", "reset-code");
    verify(domainUserJwtService, never()).generateToken(user);
  }
}
