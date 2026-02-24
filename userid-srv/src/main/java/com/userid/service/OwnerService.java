package com.userid.service;

import com.userid.api.owner.OwnerDomainRequestDTO;
import com.userid.api.owner.OwnerRequestDTO;
import com.userid.api.owner.OwnerResponseDTO;
import com.userid.api.owner.OwnerUpdateRequestDTO;
import com.userid.dal.entity.DomainEntity;
import com.userid.dal.entity.OwnerEntity;
import com.userid.dal.entity.OwnerDomainEntity;
import com.userid.dal.entity.OwnerRoleEnum;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
import com.userid.dal.repo.OwnerSocialIdentityRepository;
import com.userid.api.client.EmailNormalizer;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class OwnerService {
  private final OwnerRepository ownerRepository;
  private final OwnerDomainRepository ownerDomainRepository;
  private final DomainRepository domainRepository;
  private final OwnerSocialIdentityRepository ownerSocialIdentityRepository;
  private final AccessService accessService;
  private final PasswordEncoder passwordEncoder;
  private final OwnerOtpService ownerOtpService;

  public OwnerResponseDTO create(Long ownerId, OwnerRequestDTO request) {
    accessService.requireAdmin(ownerId);
    String email = normalizeEmail(request.email());

    ownerRepository.findByEmail(email)
        .ifPresent(user -> {
          throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
        });

    List<Long> domainIds = request.domainIds() == null ? List.of() : request.domainIds();
    List<DomainEntity> domains = List.of();
    if (request.role() == OwnerRoleEnum.USER && !domainIds.isEmpty()) {
      domains = resolveDomains(domainIds);
    }

    String password = requirePassword(request.password());

    OwnerEntity user = OwnerEntity.builder()
        .email(email)
        .passwordHash(passwordEncoder.encode(password))
        .role(request.role())
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .active(true)
        .emailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();

    OwnerEntity saved = ownerRepository.save(user);

    if (request.role() == OwnerRoleEnum.USER && !domains.isEmpty()) {
      linkDomains(saved, domains);
    }

    return toResponse(saved);
  }

  public List<OwnerResponseDTO> list(Long ownerId) {
    accessService.requireAdmin(ownerId);
    return ownerRepository.findAll().stream()
        .map(this::toResponse)
        .collect(Collectors.toList());
  }

  public OwnerResponseDTO get(Long ownerId, Long targetUserId) {
    OwnerEntity requester = accessService.requireUser(ownerId);
    if (requester.getRole() != OwnerRoleEnum.ADMIN && !requester.getId().equals(targetUserId)) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
    }
    OwnerEntity user = ownerRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));
    return toResponse(user);
  }

  public OwnerResponseDTO addDomain(Long ownerId, Long targetUserId, OwnerDomainRequestDTO request) {
    accessService.requireAdmin(ownerId);

    OwnerEntity user = ownerRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));

    if (user.getRole() != OwnerRoleEnum.USER) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Only USER can be linked to domains");
    }

    Long domainId = request.domainId();
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));

    if (ownerDomainRepository.existsByDomainIdAndOwnerIdNot(domainId, user.getId())) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Domain already has owner");
    }

    if (!ownerDomainRepository.existsByOwnerIdAndDomainId(user.getId(), domainId)) {
      OwnerDomainEntity link = OwnerDomainEntity.builder()
          .owner(user)
          .domain(domain)
          .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
          .build();
      ownerDomainRepository.save(link);
    }

    return toResponse(user);
  }

  public OwnerResponseDTO update(Long ownerId, Long targetUserId, OwnerUpdateRequestDTO request) {
    accessService.requireAdmin(ownerId);
    OwnerEntity user = ownerRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));

    if (request.email() != null && !request.email().isBlank()
        && !normalizeEmail(request.email()).equals(normalizeEmail(user.getEmail()))) {
      String email = normalizeEmail(request.email());
      if (ownerRepository.existsByEmail(email)) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
      }
      user.setEmail(email);
    }

    if (request.password() != null && !request.password().isBlank()) {
      user.setPasswordHash(passwordEncoder.encode(request.password()));
    }

    OwnerRoleEnum previousRole = user.getRole();
    OwnerRoleEnum targetRole = request.role() != null ? request.role() : previousRole;
    user.setRole(targetRole);

    if (targetRole == OwnerRoleEnum.ADMIN) {
      if (previousRole == OwnerRoleEnum.USER) {
        ensureDomainsHaveOtherOwners(user.getId(), currentDomainIds(user.getId()));
        ownerDomainRepository.deleteByOwnerId(user.getId());
      }
    } else {
      List<Long> domainIds = request.domainIds();
      if (domainIds != null) {
        List<Long> existing = currentDomainIds(user.getId());
        List<Long> removed = existing.stream()
            .filter(id -> !domainIds.contains(id))
            .distinct()
            .toList();
        ensureDomainsHaveOtherOwners(user.getId(), removed);
        List<DomainEntity> domains = domainIds.isEmpty() ? List.of() : resolveDomains(domainIds);
        ownerDomainRepository.deleteByOwnerId(user.getId());
        if (!domains.isEmpty()) {
          linkDomains(user, domains);
        }
      } else if (previousRole == OwnerRoleEnum.USER) {
        // keep existing links
      }
    }

    OwnerEntity saved = ownerRepository.save(user);
    return toResponse(saved);
  }

  public void removeDomain(Long ownerId, Long targetUserId, Long domainId) {
    accessService.requireAdmin(ownerId);
    OwnerEntity user = ownerRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));
    if (user.getRole() != OwnerRoleEnum.USER) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Only USER can be linked to domains");
    }
    ensureDomainsHaveOtherOwners(user.getId(), List.of(domainId));
    ownerDomainRepository.deleteByOwnerIdAndDomainId(user.getId(), domainId);
  }

  @Transactional
  public void delete(Long ownerId, Long targetUserId) {
    accessService.requireAdmin(ownerId);
    OwnerEntity user = ownerRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));
    ensureDomainsHaveOtherOwners(user.getId(), currentDomainIds(user.getId()));
    ownerOtpService.clearAllCodes(user);
    ownerDomainRepository.deleteByOwnerId(user.getId());
    ownerSocialIdentityRepository.deleteByOwnerId(user.getId());
    ownerRepository.delete(user);
  }

  private List<DomainEntity> resolveDomains(List<Long> domainIds) {
    List<DomainEntity> domains = domainRepository.findAllById(domainIds);
    if (domains.size() != domainIds.size()) {
      Set<Long> foundIds = domains.stream().map(DomainEntity::getId).collect(Collectors.toSet());
      List<Long> missing = domainIds.stream()
          .filter(id -> !foundIds.contains(id))
          .toList();
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown domain ids: " + missing);
    }
    return domains;
  }

  private void linkDomains(OwnerEntity user, List<DomainEntity> domains) {
    List<OwnerDomainEntity> links = new ArrayList<>();
    for (DomainEntity domain : domains) {
      OwnerDomainEntity link = OwnerDomainEntity.builder()
          .owner(user)
          .domain(domain)
          .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
          .build();
      links.add(link);
    }
    ownerDomainRepository.saveAll(links);
  }

  private OwnerResponseDTO toResponse(OwnerEntity user) {
    List<Long> domainIds;
    if (user.getRole() == OwnerRoleEnum.ADMIN) {
      domainIds = Collections.emptyList();
    } else {
      domainIds = ownerDomainRepository.findByOwnerId(user.getId()).stream()
          .map(link -> link.getDomain().getId())
          .distinct()
          .collect(Collectors.toList());
    }

    return new OwnerResponseDTO(
        user.getId(),
        user.getEmail(),
        user.getRole(),
        user.getCreatedAt(),
        domainIds
    );
  }

  private List<Long> currentDomainIds(Long userId) {
    return ownerDomainRepository.findByOwnerId(userId).stream()
        .map(link -> link.getDomain().getId())
        .distinct()
        .collect(Collectors.toList());
  }

  private void ensureDomainsHaveOtherOwners(Long userId, List<Long> domainIds) {
    for (Long domainId : domainIds) {
      long remaining = ownerDomainRepository.countByDomainIdAndOwnerRoleAndOwnerIdNot(
          domainId,
          OwnerRoleEnum.USER,
          userId
      );
      if (remaining == 0) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Domain must have owner");
      }
    }
  }

  private static String requirePassword(String password) {
    if (password == null || password.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required");
    }
    return password;
  }

  private String normalizeEmail(String email) {
    return EmailNormalizer.normalizeNullable(email);
  }
}
