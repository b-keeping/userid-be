package com.userid.service;

import com.userid.dal.entity.OtpType;
import com.userid.dal.entity.OtpUser;
import com.userid.dal.entity.User;
import com.userid.dal.repo.OtpUserRepository;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class UserOtpService {
  private final OtpUserRepository otpUserRepository;
  private final long verificationHours;
  private final long resetHours;

  public UserOtpService(
      OtpUserRepository otpUserRepository,
      @Value("${auth.user.otp-hours:24}") long verificationHours,
      @Value("${auth.user.reset-hours:2}") long resetHours
  ) {
    this.otpUserRepository = otpUserRepository;
    this.verificationHours = verificationHours;
    this.resetHours = resetHours;
  }

  public String createVerificationCode(User user) {
    return createCode(user, OtpType.VERIFICATION, verificationHours);
  }

  public String reuseVerificationCode(User user) {
    if (user.getId() == null) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User must be saved before OTP");
    }
    OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
    return otpUserRepository.findTopByUserIdAndTypeOrderByCreatedAtDesc(user.getId(), OtpType.VERIFICATION)
        .map(otp -> {
          if (now.isAfter(otp.getExpiresAt())) {
            otp.setCreatedAt(now);
            otp.setExpiresAt(now.plusHours(verificationHours));
            otpUserRepository.save(otp);
          }
          return otp.getCode();
        })
        .orElseGet(() -> createVerificationCode(user));
  }

  public String createResetCode(User user) {
    return createCode(user, OtpType.RESET, resetHours);
  }

  public OtpUser requireValid(OtpType type, String code) {
    if (code == null || code.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired code");
    }
    OtpUser otp = otpUserRepository.findByCodeAndType(code, type)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired code"));
    if (OffsetDateTime.now(ZoneOffset.UTC).isAfter(otp.getExpiresAt())) {
      otpUserRepository.deleteByUserIdAndType(otp.getUser().getId(), type);
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired code");
    }
    return otp;
  }

  public void clearVerificationCode(User user) {
    otpUserRepository.deleteByUserIdAndType(user.getId(), OtpType.VERIFICATION);
  }

  public void clearResetCode(User user) {
    otpUserRepository.deleteByUserIdAndType(user.getId(), OtpType.RESET);
  }

  public void clearAllCodes(User user) {
    otpUserRepository.deleteByUserId(user.getId());
  }

  private OffsetDateTime expireInHours(long hours) {
    return OffsetDateTime.now(ZoneOffset.UTC).plusHours(hours);
  }

  private String generateCode() {
    return UUID.randomUUID().toString().replace("-", "");
  }

  private String createCode(User user, OtpType type, long hours) {
    if (user.getId() == null) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User must be saved before OTP");
    }
    otpUserRepository.deleteByUserIdAndType(user.getId(), type);
    String code = null;
    for (int i = 0; i < 10; i += 1) {
      String candidate = generateCode();
      if (!otpUserRepository.existsByCodeAndType(candidate, type)) {
        code = candidate;
        break;
      }
    }
    if (code == null) {
      throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to generate OTP");
    }
    OtpUser otp = OtpUser.builder()
        .user(user)
        .type(type)
        .code(code)
        .expiresAt(expireInHours(hours))
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();
    otpUserRepository.save(otp);
    return code;
  }
}
