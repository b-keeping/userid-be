package com.userid.service;

import com.userid.api.auth.OwnerLoginRequest;
import com.userid.api.auth.OwnerLoginResponse;
import com.userid.api.auth.OwnerRegisterRequest;
import com.userid.api.auth.OwnerPasswordResetConfirmRequest;
import com.userid.api.auth.OwnerPasswordResetRequest;
import com.userid.api.owner.OwnerResponse;
import com.userid.dal.entity.Owner;
import com.userid.dal.entity.OtpOwner;
import com.userid.dal.entity.OtpType;
import com.userid.dal.entity.OwnerRole;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
import com.userid.security.JwtService;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OwnerAuthService {
  private final OwnerRepository ownerRepository;
  private final OwnerDomainRepository ownerDomainRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final EmailService emailService;
  private final OwnerOtpService ownerOtpService;
  private final String verifyBaseUrl;
  private final String resetBaseUrl;

  public OwnerAuthService(
      OwnerRepository ownerRepository,
      OwnerDomainRepository ownerDomainRepository,
      PasswordEncoder passwordEncoder,
      JwtService jwtService,
      EmailService emailService,
      OwnerOtpService ownerOtpService,
      @Value("${auth.email.verify-base-url}") String verifyBaseUrl,
      @Value("${auth.email.reset-base-url}") String resetBaseUrl
  ) {
    this.ownerRepository = ownerRepository;
    this.ownerDomainRepository = ownerDomainRepository;
    this.passwordEncoder = passwordEncoder;
    this.jwtService = jwtService;
    this.emailService = emailService;
    this.ownerOtpService = ownerOtpService;
    this.verifyBaseUrl = verifyBaseUrl;
    this.resetBaseUrl = resetBaseUrl;
  }

  public OwnerLoginResponse login(OwnerLoginRequest request) {
    Owner user = ownerRepository.findByEmail(request.email())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }
    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Email is not confirmed");
    }

    String token = jwtService.generateToken(user);
    return new OwnerLoginResponse(token, toResponse(user));
  }

  @Transactional
  public OwnerResponse register(OwnerRegisterRequest request) {
    Owner existing = ownerRepository.findByEmail(request.email()).orElse(null);

    if (existing != null) {
      if (existing.isActive()) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
      }
      existing.setPasswordHash(passwordEncoder.encode(request.password()));
      existing.setActive(false);
      existing.setEmailVerifiedAt(null);
      Owner saved = ownerRepository.save(existing);
      ownerOtpService.clearResetCode(saved);
      String code = ownerOtpService.createVerificationCode(saved);
      emailService.sendVerificationEmail(saved.getEmail(), buildVerificationLink(code));
      return toResponse(saved);
    }

    Owner user = Owner.builder()
        .email(request.email())
        .passwordHash(passwordEncoder.encode(request.password()))
        .role(OwnerRole.USER)
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .active(false)
        .build();

    Owner saved = ownerRepository.save(user);
    String code = ownerOtpService.createVerificationCode(saved);
    emailService.sendVerificationEmail(saved.getEmail(), buildVerificationLink(code));
    return toResponse(saved);
  }

  @Transactional
  public void confirm(String token) {
    if (token == null || token.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token is required");
    }
    OtpOwner otp = ownerOtpService.requireValid(OtpType.VERIFICATION, token);
    Owner user = otp.getOwner();
    if (!user.isActive()) {
      user.setActive(true);
      user.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
      ownerRepository.save(user);
    }
    ownerOtpService.clearVerificationCode(user);
  }

  @Transactional
  public void requestPasswordReset(OwnerPasswordResetRequest request) {
    Owner user = ownerRepository.findByEmail(request.email())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Email not found"));

    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is not confirmed");
    }
    String code = ownerOtpService.createResetCode(user);
    ownerRepository.save(user);
    emailService.sendPasswordResetEmail(user.getEmail(), buildResetLink(code));
  }

  @Transactional
  public void resetPassword(OwnerPasswordResetConfirmRequest request) {
    OtpOwner otp = ownerOtpService.requireValid(OtpType.RESET, request.token());
    Owner user = otp.getOwner();
    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is not confirmed");
    }
    user.setPasswordHash(passwordEncoder.encode(request.password()));
    ownerRepository.save(user);
    ownerOtpService.clearResetCode(user);
  }


  private OwnerResponse toResponse(Owner user) {
    List<Long> domainIds;
    if (user.getRole() == OwnerRole.ADMIN) {
      domainIds = Collections.emptyList();
    } else {
      domainIds = ownerDomainRepository.findByOwnerId(user.getId()).stream()
          .map(link -> link.getDomain().getId())
          .distinct()
          .toList();
    }

    return new OwnerResponse(
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

}
