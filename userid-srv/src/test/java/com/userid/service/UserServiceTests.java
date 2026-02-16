package com.userid.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.userid.api.user.UserRegistrationRequest;
import com.userid.dal.entity.Domain;
import com.userid.dal.entity.User;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.ProfileFieldRepository;
import com.userid.dal.repo.UserProfileValueRepository;
import com.userid.dal.repo.UserRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class UserServiceTests {
  @Mock
  private DomainRepository domainRepository;
  @Mock
  private ProfileFieldRepository profileFieldRepository;
  @Mock
  private UserProfileValueRepository userProfileValueRepository;
  @Mock
  private UserRepository userRepository;
  @Mock
  private AccessService accessService;
  @Mock
  private PasswordEncoder passwordEncoder;
  @Mock
  private EmailService emailService;
  @Mock
  private UserOtpService userOtpService;

  private UserService userService;

  @BeforeEach
  void setUp() {
    userService = new UserService(
        domainRepository,
        profileFieldRepository,
        userProfileValueRepository,
        userRepository,
        accessService,
        new ObjectMapper().findAndRegisterModules(),
        passwordEncoder,
        emailService,
        userOtpService);
  }

  @Test
  void registerByDomainDuplicateKeyReturnsConflictUserAlreadyRegisteredWhenExistingUserIsConfirmed() {
    Domain domain = Domain.builder().id(12L).name("example.org").build();
    UserRegistrationRequest request = new UserRegistrationRequest("user@example.org", "secret", List.of());
    User existingConfirmed = User.builder()
        .id(101L)
        .domain(domain)
        .email("user@example.org")
        .emailPending("user@example.org")
        .passwordHash("old-hash")
        .createdAt(java.time.OffsetDateTime.now())
        .emailVerifiedAt(java.time.OffsetDateTime.now())
        .build();

    when(domainRepository.findById(12L)).thenReturn(Optional.of(domain));
    when(profileFieldRepository.findByDomainId(12L)).thenReturn(List.of());
    when(passwordEncoder.encode("secret")).thenReturn("hash");
    when(userRepository.saveAndFlush(any(User.class)))
        .thenThrow(new DataIntegrityViolationException(
            "duplicate key value violates unique constraint \"uk_users_domain_email_pending\""));
    when(userRepository.findByDomainIdAndEmail(12L, "user@example.org")).thenReturn(Optional.of(existingConfirmed));

    assertThatThrownBy(() -> userService.registerByDomain(12L, request))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining(HttpStatus.CONFLICT.toString())
        .hasMessageContaining("User already registered");

    verify(userOtpService, never()).createVerificationCode(any(User.class));
    verify(userOtpService, never()).reuseVerificationCode(any(User.class));
    verify(emailService, never()).sendOtpEmail(any(), any(), any());
  }

  @Test
  void registerByDomainDuplicateKeyUpdatesUnconfirmedUserAndResendsExistingOtp() {
    Domain domain = Domain.builder().id(12L).name("example.org").build();
    UserRegistrationRequest request = new UserRegistrationRequest("user@example.org", "secret", List.of());
    User existingUnconfirmed = User.builder()
        .id(101L)
        .domain(domain)
        .email("user@example.org")
        .emailPending("user@example.org")
        .passwordHash("old-hash")
        .createdAt(java.time.OffsetDateTime.now())
        .emailVerifiedAt(null)
        .build();

    when(domainRepository.findById(12L)).thenReturn(Optional.of(domain));
    when(profileFieldRepository.findByDomainId(12L)).thenReturn(List.of());
    when(passwordEncoder.encode("secret")).thenReturn("hash");
    when(userRepository.saveAndFlush(any(User.class)))
        .thenThrow(new DataIntegrityViolationException(
            "duplicate key value violates unique constraint \"uk_users_domain_email_pending\""))
        .thenReturn(existingUnconfirmed);
    when(userRepository.findByDomainIdAndEmail(12L, "user@example.org")).thenReturn(Optional.of(existingUnconfirmed));
    when(userOtpService.reuseVerificationCode(existingUnconfirmed)).thenReturn("otp-existing");

    userService.registerByDomain(12L, request);

    verify(userRepository, times(2)).saveAndFlush(any(User.class));
    verify(userRepository).saveAndFlush(existingUnconfirmed);
    verify(userOtpService, never()).createVerificationCode(any(User.class));
    verify(userOtpService).reuseVerificationCode(existingUnconfirmed);
    verify(emailService).sendOtpEmail(eq(domain), eq("user@example.org"), eq("otp-existing"));
  }
}
