package com.userid.service;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.userid.dal.entity.OwnerEntity;
import com.userid.dal.entity.OwnerRoleEnum;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
import com.userid.dal.repo.OwnerSocialIdentityRepository;
import java.time.OffsetDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class OwnerServiceTests {

  @Mock
  private OwnerRepository ownerRepository;
  @Mock
  private OwnerDomainRepository ownerDomainRepository;
  @Mock
  private DomainRepository domainRepository;
  @Mock
  private OwnerSocialIdentityRepository ownerSocialIdentityRepository;
  @Mock
  private AccessService accessService;
  @Mock
  private PasswordEncoder passwordEncoder;
  @Mock
  private OwnerOtpService ownerOtpService;

  private OwnerService ownerService;

  @BeforeEach
  void setUp() {
    ownerService = new OwnerService(
        ownerRepository,
        ownerDomainRepository,
        domainRepository,
        ownerSocialIdentityRepository,
        accessService,
        passwordEncoder,
        ownerOtpService);
  }

  @Test
  void deleteRemovesOwnerSocialIdentitiesBeforeOwnerDelete() {
    OwnerEntity admin = OwnerEntity.builder()
        .id(1L)
        .email("admin@userid.local")
        .role(OwnerRoleEnum.ADMIN)
        .createdAt(OffsetDateTime.now())
        .active(true)
        .build();

    OwnerEntity target = OwnerEntity.builder()
        .id(3L)
        .email("owner@example.org")
        .role(OwnerRoleEnum.USER)
        .createdAt(OffsetDateTime.now())
        .active(true)
        .build();

    when(accessService.requireAdmin(1L)).thenReturn(admin);
    when(ownerRepository.findById(3L)).thenReturn(Optional.of(target));
    when(ownerDomainRepository.findByOwnerId(3L)).thenReturn(java.util.List.of());

    ownerService.delete(1L, 3L);

    verify(ownerOtpService).clearAllCodes(target);
    verify(ownerDomainRepository).deleteByOwnerId(3L);
    verify(ownerSocialIdentityRepository).deleteByOwnerId(3L);
    verify(ownerRepository).delete(target);
  }
}
