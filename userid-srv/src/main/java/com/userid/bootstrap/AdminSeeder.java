package com.userid.bootstrap;

import com.userid.dal.entity.Owner;
import com.userid.dal.entity.OwnerRole;
import com.userid.dal.repo.OwnerRepository;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AdminSeeder implements CommandLineRunner {
  private static final String DEFAULT_ADMIN_EMAIL = "admin@userid.local";
  private static final String DEFAULT_ADMIN_PASSWORD = "123456";

  private final OwnerRepository ownerRepository;
  private final PasswordEncoder passwordEncoder;

  @Override
  public void run(String... args) {
    Owner existing = ownerRepository.findFirstByRole(OwnerRole.ADMIN).orElse(null);
    if (existing != null) {
      boolean changed = false;
      if (existing.getEmail() == null || existing.getEmail().isBlank()) {
        existing.setEmail(DEFAULT_ADMIN_EMAIL);
        changed = true;
      }
      if (!existing.isActive()) {
        existing.setActive(true);
        existing.setEmailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC));
        changed = true;
      }
      if (changed) {
        ownerRepository.save(existing);
      }
      return;
    }

    Owner admin = Owner.builder()
        .email(DEFAULT_ADMIN_EMAIL)
        .passwordHash(passwordEncoder.encode(DEFAULT_ADMIN_PASSWORD))
        .role(OwnerRole.ADMIN)
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .active(true)
        .emailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();

    ownerRepository.save(admin);
  }
}
