package com.userid.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.userid.api.common.ApiMessage;
import com.userid.api.user.UserConfirmRequest;
import com.userid.api.user.UserForgotPasswordRequest;
import com.userid.dal.entity.Domain;
import com.userid.dal.entity.OtpType;
import com.userid.dal.entity.OtpUser;
import com.userid.dal.entity.User;
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
    Domain domain = Domain.builder().id(7L).name("example.org").build();
    User user = User.builder()
        .domain(domain)
        .emailPending("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .build();
    OtpUser otp = OtpUser.builder().user(user).type(OtpType.VERIFICATION).code("abc123").build();

    when(userOtpService.requireValid(OtpType.VERIFICATION, "abc123")).thenReturn(otp);

    ApiMessage response = domainUserAuthService.confirm(7L, new UserConfirmRequest("abc123"));

    assertThat(response.message()).isEqualTo("ok");
    assertThat(user.getEmail()).isEqualTo("user@example.org");
    assertThat(user.getEmailVerifiedAt()).isNotNull();
    verify(userOtpService).clearVerificationCode(user);
    verify(userRepository).saveAndFlush(user);
  }

  @Test
  void confirmByCodeRejectsDomainMismatch() {
    Domain domain = Domain.builder().id(7L).name("example.org").build();
    User user = User.builder()
        .domain(domain)
        .emailPending("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .build();
    OtpUser otp = OtpUser.builder().user(user).type(OtpType.VERIFICATION).code("abc123").build();

    when(userOtpService.requireValid(OtpType.VERIFICATION, "abc123")).thenReturn(otp);

    assertThatThrownBy(() -> domainUserAuthService.confirm(99L, new UserConfirmRequest("abc123")))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining(HttpStatus.FORBIDDEN.toString());
  }

  @Test
  void forgotPasswordWhenEmailNotConfirmedResendsVerificationAndReturnsOk() {
    Domain domain = Domain.builder().id(7L).name("example.org").build();
    User user = User.builder()
        .domain(domain)
        .email("user@example.org")
        .emailPending("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .emailVerifiedAt(null)
        .build();
    when(userRepository.findByDomainIdAndEmail(7L, "user@example.org")).thenReturn(java.util.Optional.of(user));
    when(userOtpService.createVerificationCode(user)).thenReturn("verify-code");

    ApiMessage response = domainUserAuthService.forgotPassword(7L, new UserForgotPasswordRequest("user@example.org"));

    assertThat(response.message()).isEqualTo("ok");
    verify(userOtpService).createVerificationCode(user);
    verify(emailService).sendOtpEmail(domain, "user@example.org", "verify-code");
    verify(userOtpService, never()).createResetCode(user);
    verify(emailService, never()).sendUserPasswordResetCode(domain, "user@example.org", "verify-code");
    verify(userRepository, never()).save(user);
  }

  @Test
  void forgotPasswordWhenEmailConfirmedSendsResetCode() {
    Domain domain = Domain.builder().id(7L).name("example.org").build();
    User user = User.builder()
        .domain(domain)
        .email("user@example.org")
        .emailPending("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .emailVerifiedAt(OffsetDateTime.now())
        .build();
    when(userRepository.findByDomainIdAndEmail(7L, "user@example.org")).thenReturn(java.util.Optional.of(user));
    when(userOtpService.createResetCode(user)).thenReturn("reset-code");

    ApiMessage response = domainUserAuthService.forgotPassword(7L, new UserForgotPasswordRequest("user@example.org"));

    assertThat(response.message()).isEqualTo("ok");
    verify(userOtpService).createResetCode(user);
    verify(userRepository).save(user);
    verify(emailService).sendUserPasswordResetCode(domain, "user@example.org", "reset-code");
    verify(userOtpService, never()).createVerificationCode(user);
  }
}
