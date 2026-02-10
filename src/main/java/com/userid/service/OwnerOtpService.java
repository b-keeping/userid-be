package com.userid.service;

import com.userid.dal.entity.OtpOwner;
import com.userid.dal.entity.OtpType;
import com.userid.dal.entity.Owner;
import com.userid.dal.repo.OtpOwnerRepository;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class OwnerOtpService {
  private final OtpOwnerRepository otpOwnerRepository;
  private final long verificationHours;
  private final long resetHours;

  public OwnerOtpService(
      OtpOwnerRepository otpOwnerRepository,
      @Value("${auth.email.verification-hours:24}") long verificationHours,
      @Value("${auth.email.reset-hours:2}") long resetHours
  ) {
    this.otpOwnerRepository = otpOwnerRepository;
    this.verificationHours = verificationHours;
    this.resetHours = resetHours;
  }

  public String createVerificationCode(Owner owner) {
    return createCode(owner, OtpType.VERIFICATION, verificationHours);
  }

  public String createResetCode(Owner owner) {
    return createCode(owner, OtpType.RESET, resetHours);
  }

  public OtpOwner requireValid(OtpType type, String code) {
    if (code == null || code.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired code");
    }
    OtpOwner otp = otpOwnerRepository.findByCodeAndType(code, type)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired code"));
    if (OffsetDateTime.now(ZoneOffset.UTC).isAfter(otp.getExpiresAt())) {
      otpOwnerRepository.deleteByOwnerIdAndType(otp.getOwner().getId(), type);
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired code");
    }
    return otp;
  }

  public void clearVerificationCode(Owner owner) {
    otpOwnerRepository.deleteByOwnerIdAndType(owner.getId(), OtpType.VERIFICATION);
  }

  public void clearResetCode(Owner owner) {
    otpOwnerRepository.deleteByOwnerIdAndType(owner.getId(), OtpType.RESET);
  }

  public void clearAllCodes(Owner owner) {
    otpOwnerRepository.deleteByOwnerId(owner.getId());
  }

  private OffsetDateTime expireInHours(long hours) {
    return OffsetDateTime.now(ZoneOffset.UTC).plusHours(hours);
  }

  private String generateCode() {
    return UUID.randomUUID().toString().replace("-", "");
  }

  private String createCode(Owner owner, OtpType type, long hours) {
    if (owner.getId() == null) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Owner must be saved before OTP");
    }
    otpOwnerRepository.deleteByOwnerIdAndType(owner.getId(), type);
    String code = null;
    for (int i = 0; i < 10; i += 1) {
      String candidate = generateCode();
      if (!otpOwnerRepository.existsByCodeAndType(candidate, type)) {
        code = candidate;
        break;
      }
    }
    if (code == null) {
      throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to generate OTP");
    }
    OtpOwner otp = OtpOwner.builder()
        .owner(owner)
        .type(type)
        .code(code)
        .expiresAt(expireInHours(hours))
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();
    otpOwnerRepository.save(otp);
    return code;
  }
}
