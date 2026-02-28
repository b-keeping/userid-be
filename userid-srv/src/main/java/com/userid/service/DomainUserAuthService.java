package com.userid.service;

import com.userid.api.common.ApiMessageDTO;
import com.userid.api.user.UserConfirmRequestDTO;
import com.userid.api.user.UserForgotPasswordRequestDTO;
import com.userid.api.user.UserLoginRequestDTO;
import com.userid.api.user.UserLoginResponseDTO;
import com.userid.api.user.UserProfileValueResponseDTO;
import com.userid.api.user.UserRegistrationRequestDTO;
import com.userid.api.user.UserResetPasswordRequestDTO;
import com.userid.api.user.UserResponseDTO;
import com.userid.api.user.UserSelfUpdateRequestDTO;
import com.userid.dal.entity.OtpTypeEnum;
import com.userid.dal.entity.OtpUserEntity;
import com.userid.dal.entity.UserEntity;
import com.userid.dal.repo.UserRepository;
import com.userid.security.DomainUserJwtService;
import com.userid.security.DomainUserPrincipalDTO;
import com.userid.api.client.EmailNormalizer;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class DomainUserAuthService {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final DomainUserJwtService domainUserJwtService;
  private final UserOtpService userOtpService;
  private final EmailService emailService;
  private final UserService userService;

  public UserLoginResponseDTO register(Long domainId, UserRegistrationRequestDTO request) {
    String normalizedEmail = EmailNormalizer.normalizeNullable(request.email());
    try {
      UserResponseDTO user = userService.registerByDomain(domainId, request);
      return new UserLoginResponseDTO(null, toAuthResponse(domainId, user));
    } catch (ResponseStatusException ex) {
      if (ex.getStatusCode().value() != HttpStatus.CONFLICT.value()) {
        throw ex;
      }
      try {
        return login(domainId, new UserLoginRequestDTO(normalizedEmail, request.password()));
      } catch (ResponseStatusException loginEx) {
        if (loginEx.getStatusCode().value() != HttpStatus.UNAUTHORIZED.value()) {
          throw loginEx;
        }
        UserEntity existing = sendPasswordRecoveryBestEffort(domainId, normalizedEmail);
        return new UserLoginResponseDTO(null, existing == null ? null : toAuthResponse(existing));
      }
    }
  }

  public UserLoginResponseDTO login(Long domainId, UserLoginRequestDTO request) {
    String email = EmailNormalizer.normalizeNullable(request.email());
    UserEntity user = userRepository.findByDomainIdAndEmail(domainId, email)
        .or(() -> userRepository.findByDomainIdAndEmailPending(domainId, email))
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

    if (user.getEmailVerifiedAt() == null) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Email is not confirmed");
    }
    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User is not active");
    }
    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }

    String token = domainUserJwtService.generateToken(user);
    return new UserLoginResponseDTO(token, toAuthResponse(user));
  }

  @Transactional
  public UserLoginResponseDTO confirm(Long domainId, UserConfirmRequestDTO request) {
    OtpUserEntity otp = userOtpService.requireValid(OtpTypeEnum.VERIFICATION, request.code());
    UserEntity user = otp.getUser();
    if (!domainId.equals(user.getDomain().getId())) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Domain mismatch");
    }
    String pendingEmail = resolveVerificationEmail(user);
    user.setEmail(pendingEmail);
    user.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
    user.setActive(true);
    try {
      userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      if (isDuplicateUserEmailViolation(ex)) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered");
      }
      throw ex;
    }
    userOtpService.clearVerificationCode(user);
    String token = domainUserJwtService.generateToken(user);
    return new UserLoginResponseDTO(token, toAuthResponse(user));
  }

  public ApiMessageDTO forgotPassword(Long domainId, UserForgotPasswordRequestDTO request) {
    String email = EmailNormalizer.normalizeNullable(request.email());
    UserEntity user = userRepository.findByDomainIdAndEmail(domainId, email)
        .or(() -> userRepository.findByDomainIdAndEmailPending(domainId, email))
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    if (user.getEmailVerifiedAt() == null) {
      String verificationCode = userOtpService.createVerificationCode(user);
      emailService.sendOtpEmail(user.getDomain(), resolveVerificationEmail(user), verificationCode);
      return new ApiMessageDTO("ok");
    }
    String code = userOtpService.createResetCode(user);
    userRepository.save(user);
    emailService.sendUserPasswordResetCode(user.getDomain(), user.getEmail(), code);
    return new ApiMessageDTO("ok");
  }

  public ApiMessageDTO resetPassword(Long domainId, UserResetPasswordRequestDTO request) {
    OtpUserEntity otp = userOtpService.requireValid(OtpTypeEnum.RESET, request.code());
    UserEntity user = otp.getUser();
    if (!domainId.equals(user.getDomain().getId())) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Domain mismatch");
    }
    user.setPasswordHash(passwordEncoder.encode(request.password()));
    userOtpService.clearResetCode(user);
    userRepository.save(user);
    return new ApiMessageDTO("ok");
  }

  public UserResponseDTO updateSelf(Long domainId, HttpServletRequest request, UserSelfUpdateRequestDTO body) {
    DomainUserPrincipalDTO principal = parsePrincipal(request);
    if (!principal.domainId().equals(domainId)) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Domain mismatch");
    }
    UserEntity user = userRepository.findByIdAndDomainId(principal.id(), domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

    if (body.password() != null && !body.password().isBlank()) {
      user.setPasswordHash(passwordEncoder.encode(body.password()));
    }
    if (body.values() != null) {
      userService.applyProfileValues(user, domainId, body.values());
      if (!user.isActive()) {
        user.setActive(true);
      }
    }
    UserEntity saved = userRepository.saveAndFlush(user);
    return userService.toResponse(saved);
  }

  public ApiMessageDTO resendVerification(Long domainId, UserForgotPasswordRequestDTO request) {
    String email = EmailNormalizer.normalizeNullable(request.email());
    UserEntity user = userRepository.findByDomainIdAndEmail(domainId, email)
        .or(() -> userRepository.findByDomainIdAndEmailPending(domainId, email))
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    String code = userOtpService.createVerificationCode(user);
    emailService.sendOtpEmail(user.getDomain(), resolveVerificationEmail(user), code);
    return new ApiMessageDTO("ok");
  }

  private DomainUserPrincipalDTO parsePrincipal(HttpServletRequest request) {
    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (header == null || !header.startsWith("Bearer ")) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing token");
    }
    String token = header.substring(7).trim();
    if (token.isEmpty()) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing token");
    }
    try {
      return domainUserJwtService.parseToken(token);
    } catch (Exception ex) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token");
    }
  }

  private UserResponseDTO toAuthResponse(UserEntity user) {
    return new UserResponseDTO(
        user.getId(),
        user.getDomain().getId(),
        user.getEmail(),
        user.getEmailVerifiedAt() != null,
        user.isActive(),
        user.getCreatedAt(),
        resolveValues(user)
    );
  }

  private UserResponseDTO toAuthResponse(Long domainId, UserResponseDTO user) {
    return new UserResponseDTO(
        user.id(),
        domainId,
        user.email(),
        user.confirmed(),
        user.active(),
        user.createdAt(),
        user.values()
    );
  }

  private List<UserProfileValueResponseDTO> resolveValues(UserEntity user) {
    UserResponseDTO response = userService.toResponse(user);
    if (response == null || response.values() == null) {
      return List.of();
    }
    return response.values();
  }

  private String resolveVerificationEmail(UserEntity user) {
    if (user.getEmailPending() != null && !user.getEmailPending().isBlank()) {
      return user.getEmailPending();
    }
    if (user.getEmail() != null && !user.getEmail().isBlank()) {
      return user.getEmail();
    }
    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User email is not set");
  }

  private UserEntity sendPasswordRecoveryBestEffort(Long domainId, String email) {
    try {
      UserEntity user = userRepository.findByDomainIdAndEmail(domainId, email)
          .or(() -> userRepository.findByDomainIdAndEmailPending(domainId, email))
          .orElse(null);
      if (user == null) {
        return null;
      }
      if (user.getEmailVerifiedAt() == null) {
        String verificationCode = userOtpService.createVerificationCode(user);
        emailService.sendOtpEmail(user.getDomain(), resolveVerificationEmail(user), verificationCode);
        return user;
      }
      String code = userOtpService.createResetCode(user);
      userRepository.save(user);
      emailService.sendUserPasswordResetCode(user.getDomain(), user.getEmail(), code);
      return user;
    } catch (Exception ex) {
      log.warn(
          "Register conflict recovery flow failed domainId={} email={} reason={}",
          domainId,
          email,
          ex.getMessage());
      return null;
    }
  }

  private boolean isDuplicateUserEmailViolation(DataIntegrityViolationException ex) {
    String message = ex.getMessage();
    if (message == null) {
      return false;
    }
    String normalized = message.toLowerCase();
    return normalized.contains("uk_users_domain_email")
        || normalized.contains("uk_users_domain_email_pending")
        || normalized.contains("duplicate key")
        || normalized.contains("unique index or primary key violation");
  }
}
