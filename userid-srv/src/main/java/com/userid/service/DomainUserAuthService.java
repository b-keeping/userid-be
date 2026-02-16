package com.userid.service;

import com.userid.api.common.ApiMessage;
import com.userid.api.user.UserAuthResponse;
import com.userid.api.user.UserConfirmRequest;
import com.userid.api.user.UserForgotPasswordRequest;
import com.userid.api.user.UserLoginRequest;
import com.userid.api.user.UserLoginResponse;
import com.userid.api.user.UserResetPasswordRequest;
import com.userid.api.user.UserResponse;
import com.userid.api.user.UserSelfUpdateRequest;
import com.userid.dal.entity.OtpType;
import com.userid.dal.entity.OtpUser;
import com.userid.dal.entity.User;
import com.userid.dal.repo.UserRepository;
import com.userid.security.DomainUserJwtService;
import com.userid.security.DomainUserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class DomainUserAuthService {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final DomainUserJwtService domainUserJwtService;
  private final UserOtpService userOtpService;
  private final EmailService emailService;
  private final UserService userService;

  public UserLoginResponse login(Long domainId, UserLoginRequest request) {
    User user = userRepository.findByDomainIdAndEmail(domainId, request.email())
        .or(() -> userRepository.findByDomainIdAndEmailPending(domainId, request.email()))
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

    if (user.getEmailVerifiedAt() == null) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Email is not confirmed");
    }
    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }

    String token = domainUserJwtService.generateToken(user);
    return new UserLoginResponse(token, toAuthResponse(user));
  }

  @Transactional
  public ApiMessage confirm(Long domainId, UserConfirmRequest request) {
    OtpUser otp = userOtpService.requireValid(OtpType.VERIFICATION, request.code());
    User user = otp.getUser();
    if (!domainId.equals(user.getDomain().getId())) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Domain mismatch");
    }
    String pendingEmail = resolveVerificationEmail(user);
    user.setEmail(pendingEmail);
    user.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
    try {
      userRepository.saveAndFlush(user);
    } catch (DataIntegrityViolationException ex) {
      if (isDuplicateUserEmailViolation(ex)) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered");
      }
      throw ex;
    }
    userOtpService.clearVerificationCode(user);
    return new ApiMessage("ok");
  }

  public ApiMessage forgotPassword(Long domainId, UserForgotPasswordRequest request) {
    User user = userRepository.findByDomainIdAndEmail(domainId, request.email())
        .or(() -> userRepository.findByDomainIdAndEmailPending(domainId, request.email()))
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    if (user.getEmailVerifiedAt() == null) {
      String verificationCode = userOtpService.createVerificationCode(user);
      emailService.sendOtpEmail(user.getDomain(), resolveVerificationEmail(user), verificationCode);
      return new ApiMessage("ok");
    }
    String code = userOtpService.createResetCode(user);
    userRepository.save(user);
    emailService.sendUserPasswordResetCode(user.getDomain(), user.getEmail(), code);
    return new ApiMessage("ok");
  }

  public ApiMessage resetPassword(Long domainId, UserResetPasswordRequest request) {
    OtpUser otp = userOtpService.requireValid(OtpType.RESET, request.code());
    User user = otp.getUser();
    if (!domainId.equals(user.getDomain().getId())) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Domain mismatch");
    }
    user.setPasswordHash(passwordEncoder.encode(request.password()));
    userOtpService.clearResetCode(user);
    userRepository.save(user);
    return new ApiMessage("ok");
  }

  public UserResponse updateSelf(Long domainId, HttpServletRequest request, UserSelfUpdateRequest body) {
    DomainUserPrincipal principal = parsePrincipal(request);
    if (!principal.domainId().equals(domainId)) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Domain mismatch");
    }
    User user = userRepository.findByIdAndDomainId(principal.id(), domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

    if (body.password() != null && !body.password().isBlank()) {
      user.setPasswordHash(passwordEncoder.encode(body.password()));
    }
    if (body.values() != null) {
      userService.applyProfileValues(user, domainId, body.values());
    }
    User saved = userRepository.save(user);
    return userService.toResponse(saved);
  }

  public ApiMessage resendVerification(Long domainId, UserForgotPasswordRequest request) {
    User user = userRepository.findByDomainIdAndEmail(domainId, request.email())
        .or(() -> userRepository.findByDomainIdAndEmailPending(domainId, request.email()))
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    String code = userOtpService.createVerificationCode(user);
    emailService.sendOtpEmail(user.getDomain(), resolveVerificationEmail(user), code);
    return new ApiMessage("ok");
  }

  private DomainUserPrincipal parsePrincipal(HttpServletRequest request) {
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

  private UserAuthResponse toAuthResponse(User user) {
    return new UserAuthResponse(
        user.getId(),
        user.getDomain().getId(),
        user.getEmail(),
        user.getEmailVerifiedAt() != null,
        user.getCreatedAt()
    );
  }

  private String resolveVerificationEmail(User user) {
    if (user.getEmailPending() != null && !user.getEmailPending().isBlank()) {
      return user.getEmailPending();
    }
    if (user.getEmail() != null && !user.getEmail().isBlank()) {
      return user.getEmail();
    }
    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User email is not set");
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
