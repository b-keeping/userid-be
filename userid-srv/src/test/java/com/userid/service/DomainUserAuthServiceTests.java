package com.userid.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.userid.api.common.ApiMessage;
import com.userid.api.user.UserConfirmRequest;
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
        .email("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .build();
    OtpUser otp = OtpUser.builder().user(user).type(OtpType.VERIFICATION).code("abc123").build();

    when(userOtpService.requireValid(OtpType.VERIFICATION, "abc123")).thenReturn(otp);

    ApiMessage response = domainUserAuthService.confirm(7L, new UserConfirmRequest("abc123"));

    assertThat(response.message()).isEqualTo("ok");
    assertThat(user.getEmailVerifiedAt()).isNotNull();
    verify(userOtpService).clearVerificationCode(user);
    verify(userRepository).save(user);
  }

  @Test
  void confirmByCodeRejectsDomainMismatch() {
    Domain domain = Domain.builder().id(7L).name("example.org").build();
    User user = User.builder()
        .domain(domain)
        .email("user@example.org")
        .passwordHash("hash")
        .createdAt(OffsetDateTime.now())
        .build();
    OtpUser otp = OtpUser.builder().user(user).type(OtpType.VERIFICATION).code("abc123").build();

    when(userOtpService.requireValid(OtpType.VERIFICATION, "abc123")).thenReturn(otp);

    assertThatThrownBy(() -> domainUserAuthService.confirm(99L, new UserConfirmRequest("abc123")))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining(HttpStatus.FORBIDDEN.toString());
  }
}
