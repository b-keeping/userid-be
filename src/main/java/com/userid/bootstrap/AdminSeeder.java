package com.userid.bootstrap;

import com.userid.dal.entity.ServiceUser;
import com.userid.dal.entity.ServiceUserRole;
import com.userid.dal.repo.ServiceUserRepository;
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

  private final ServiceUserRepository serviceUserRepository;
  private final PasswordEncoder passwordEncoder;

  @Override
  public void run(String... args) {
    if (serviceUserRepository.existsByRole(ServiceUserRole.ADMIN)) {
      return;
    }

    ServiceUser admin = ServiceUser.builder()
        .username(DEFAULT_ADMIN_USERNAME)
        .passwordHash(passwordEncoder.encode(DEFAULT_ADMIN_PASSWORD))
        .role(ServiceUserRole.ADMIN)
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();

    serviceUserRepository.save(admin);
  }
}
