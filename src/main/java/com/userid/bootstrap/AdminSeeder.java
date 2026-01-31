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
  private static final String DEFAULT_ADMIN_USERNAME = "admin";
  private static final String DEFAULT_ADMIN_PASSWORD = "123456";

  private final OwnerRepository ownerRepository;
  private final PasswordEncoder passwordEncoder;

  @Override
  public void run(String... args) {
    if (ownerRepository.existsByRole(OwnerRole.ADMIN)) {
      return;
    }

    Owner admin = Owner.builder()
        .username(DEFAULT_ADMIN_USERNAME)
        .passwordHash(passwordEncoder.encode(DEFAULT_ADMIN_PASSWORD))
        .role(OwnerRole.ADMIN)
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();

    ownerRepository.save(admin);
  }
}
