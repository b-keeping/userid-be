package com.userid.service;

import com.userid.dal.entity.User;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserOtpService {
  private final PasswordEncoder passwordEncoder;
  private final SecureRandom random = new SecureRandom();
  private final long verificationHours;
  private final long resetHours;

  public UserOtpService(
      PasswordEncoder passwordEncoder,
      @Value("${auth.user.otp-hours:24}") long verificationHours,
      @Value("${auth.user.reset-hours:2}") long resetHours
  ) {
    this.passwordEncoder = passwordEncoder;
    this.verificationHours = verificationHours;
    this.resetHours = resetHours;
  }

  public String createVerificationCode(User user) {
    String code = generateCode();
    user.setOtpHash(passwordEncoder.encode(code));
    user.setOtpExpiresAt(expireInHours(verificationHours));
    return code;
  }

  public String createResetCode(User user) {
    String code = generateCode();
    user.setResetHash(passwordEncoder.encode(code));
    user.setResetExpiresAt(expireInHours(resetHours));
    return code;
  }

  public boolean verifyCode(User user, String code) {
    if (code == null || code.isBlank()) {
      return false;
    }
    if (user.getOtpHash() == null || user.getOtpExpiresAt() == null) {
      return false;
    }
    if (OffsetDateTime.now(ZoneOffset.UTC).isAfter(user.getOtpExpiresAt())) {
      return false;
    }
    return passwordEncoder.matches(code, user.getOtpHash());
  }

  public boolean verifyResetCode(User user, String code) {
    if (code == null || code.isBlank()) {
      return false;
    }
    if (user.getResetHash() == null || user.getResetExpiresAt() == null) {
      return false;
    }
    if (OffsetDateTime.now(ZoneOffset.UTC).isAfter(user.getResetExpiresAt())) {
      return false;
    }
    return passwordEncoder.matches(code, user.getResetHash());
  }

  public void clearVerificationCode(User user) {
    user.setOtpHash(null);
    user.setOtpExpiresAt(null);
  }

  public void clearResetCode(User user) {
    user.setResetHash(null);
    user.setResetExpiresAt(null);
  }

  private OffsetDateTime expireInHours(long hours) {
    return OffsetDateTime.now(ZoneOffset.UTC).plusHours(hours);
  }

  private String generateCode() {
    int value = random.nextInt(900000) + 100000;
    return String.valueOf(value);
  }
}
