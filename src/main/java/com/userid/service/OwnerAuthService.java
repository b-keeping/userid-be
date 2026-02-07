package com.userid.service;

import com.userid.api.auth.OwnerLoginRequest;
import com.userid.api.auth.OwnerLoginResponse;
import com.userid.api.auth.OwnerRegisterRequest;
import com.userid.api.auth.OwnerPasswordResetConfirmRequest;
import com.userid.api.auth.OwnerPasswordResetRequest;
import com.userid.api.owner.OwnerResponse;
import com.userid.dal.entity.Owner;
import com.userid.dal.entity.OwnerRole;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
import com.userid.security.JwtService;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
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
  private final String verifyBaseUrl;
  private final String resetBaseUrl;
  private final long verificationHours;
  private final long resetHours;

  public OwnerAuthService(
      OwnerRepository ownerRepository,
      OwnerDomainRepository ownerDomainRepository,
      PasswordEncoder passwordEncoder,
      JwtService jwtService,
      EmailService emailService,
      @Value("${auth.email.verify-base-url}") String verifyBaseUrl,
      @Value("${auth.email.reset-base-url}") String resetBaseUrl,
      @Value("${auth.email.verification-hours:24}") long verificationHours,
      @Value("${auth.email.reset-hours:2}") long resetHours
  ) {
    this.ownerRepository = ownerRepository;
    this.ownerDomainRepository = ownerDomainRepository;
    this.passwordEncoder = passwordEncoder;
    this.jwtService = jwtService;
    this.emailService = emailService;
    this.verifyBaseUrl = verifyBaseUrl;
    this.resetBaseUrl = resetBaseUrl;
    this.verificationHours = verificationHours;
    this.resetHours = resetHours;
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

    String token = generateToken();
    OffsetDateTime expiresAt = OffsetDateTime.now(ZoneOffset.UTC).plusHours(verificationHours);

    if (existing != null) {
      if (existing.isActive()) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
      }
      existing.setPasswordHash(passwordEncoder.encode(request.password()));
      existing.setVerificationToken(token);
      existing.setVerificationExpiresAt(expiresAt);
      existing.setResetToken(null);
      existing.setResetExpiresAt(null);
      existing.setActive(false);
      existing.setEmailVerifiedAt(null);
      Owner saved = ownerRepository.save(existing);
      emailService.sendVerificationEmail(saved.getEmail(), buildVerificationLink(token));
      return toResponse(saved);
    }

    Owner user = Owner.builder()
        .email(request.email())
        .passwordHash(passwordEncoder.encode(request.password()))
        .role(OwnerRole.USER)
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .active(false)
        .verificationToken(token)
        .verificationExpiresAt(expiresAt)
        .build();

    Owner saved = ownerRepository.save(user);
    emailService.sendVerificationEmail(saved.getEmail(), buildVerificationLink(token));
    return toResponse(saved);
  }

  @Transactional
  public void confirm(String token) {
    if (token == null || token.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token is required");
    }
    Owner user = ownerRepository.findByVerificationToken(token)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token"));

    if (user.isActive()) {
      return;
    }

    OffsetDateTime expiresAt = user.getVerificationExpiresAt();
    if (expiresAt != null && expiresAt.isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token expired");
    }

    user.setActive(true);
    user.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
    user.setVerificationToken(null);
    user.setVerificationExpiresAt(null);
    ownerRepository.save(user);
  }

  @Transactional
  public void requestPasswordReset(OwnerPasswordResetRequest request) {
    Owner user = ownerRepository.findByEmail(request.email())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Email not found"));

    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is not confirmed");
    }

    String token = generateToken();
    OffsetDateTime expiresAt = OffsetDateTime.now(ZoneOffset.UTC).plusHours(resetHours);
    user.setResetToken(token);
    user.setResetExpiresAt(expiresAt);
    ownerRepository.save(user);
    emailService.sendPasswordResetEmail(user.getEmail(), buildResetLink(token));
  }

  @Transactional
  public void resetPassword(OwnerPasswordResetConfirmRequest request) {
    Owner user = ownerRepository.findByResetToken(request.token())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token"));

    OffsetDateTime expiresAt = user.getResetExpiresAt();
    if (expiresAt != null && expiresAt.isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token expired");
    }

    if (!user.isActive()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is not confirmed");
    }

    user.setPasswordHash(passwordEncoder.encode(request.password()));
    user.setResetToken(null);
    user.setResetExpiresAt(null);
    ownerRepository.save(user);
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

  private static String generateToken() {
    return UUID.randomUUID().toString().replace("-", "");
  }
}
