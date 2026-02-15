package com.userid.service;

import com.userid.api.owner.OwnerDomainRequest;
import com.userid.api.owner.OwnerRequest;
import com.userid.api.owner.OwnerResponse;
import com.userid.api.owner.OwnerUpdateRequest;
import com.userid.dal.entity.Domain;
import com.userid.dal.entity.Owner;
import com.userid.dal.entity.OwnerDomain;
import com.userid.dal.entity.OwnerRole;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
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
  private final AccessService accessService;
  private final PasswordEncoder passwordEncoder;
  private final OwnerOtpService ownerOtpService;

  public OwnerResponse create(Long ownerId, OwnerRequest request) {
    accessService.requireAdmin(ownerId);

    ownerRepository.findByEmail(request.email())
        .ifPresent(user -> {
          throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
        });

    List<Long> domainIds = request.domainIds() == null ? List.of() : request.domainIds();
    List<Domain> domains = List.of();
    if (request.role() == OwnerRole.USER && !domainIds.isEmpty()) {
      domains = resolveDomains(domainIds);
    }

    String password = requirePassword(request.password());

    Owner user = Owner.builder()
        .email(request.email())
        .passwordHash(passwordEncoder.encode(password))
        .role(request.role())
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .active(true)
        .emailVerifiedAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();

    Owner saved = ownerRepository.save(user);

    if (request.role() == OwnerRole.USER && !domains.isEmpty()) {
      linkDomains(saved, domains);
    }

    return toResponse(saved);
  }

  public List<OwnerResponse> list(Long ownerId) {
    accessService.requireAdmin(ownerId);
    return ownerRepository.findAll().stream()
        .map(this::toResponse)
        .collect(Collectors.toList());
  }

  public OwnerResponse get(Long ownerId, Long targetUserId) {
    Owner requester = accessService.requireUser(ownerId);
    if (requester.getRole() != OwnerRole.ADMIN && !requester.getId().equals(targetUserId)) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
    }
    Owner user = ownerRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));
    return toResponse(user);
  }

  public OwnerResponse addDomain(Long ownerId, Long targetUserId, OwnerDomainRequest request) {
    accessService.requireAdmin(ownerId);

    Owner user = ownerRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));

    if (user.getRole() != OwnerRole.USER) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Only USER can be linked to domains");
    }

    Long domainId = request.domainId();
    Domain domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));

    if (ownerDomainRepository.existsByDomainIdAndOwnerIdNot(domainId, user.getId())) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Domain already has owner");
    }

    if (!ownerDomainRepository.existsByOwnerIdAndDomainId(user.getId(), domainId)) {
      OwnerDomain link = OwnerDomain.builder()
          .owner(user)
          .domain(domain)
          .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
          .build();
      ownerDomainRepository.save(link);
    }

    return toResponse(user);
  }

  public OwnerResponse update(Long ownerId, Long targetUserId, OwnerUpdateRequest request) {
    accessService.requireAdmin(ownerId);
    Owner user = ownerRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));

    if (request.email() != null && !request.email().isBlank()
        && !request.email().equals(user.getEmail())) {
      if (ownerRepository.existsByEmail(request.email())) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
      }
      user.setEmail(request.email());
    }

    if (request.password() != null && !request.password().isBlank()) {
      user.setPasswordHash(passwordEncoder.encode(request.password()));
    }

    OwnerRole previousRole = user.getRole();
    OwnerRole targetRole = request.role() != null ? request.role() : previousRole;
    user.setRole(targetRole);

    if (targetRole == OwnerRole.ADMIN) {
      if (previousRole == OwnerRole.USER) {
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
        List<Domain> domains = domainIds.isEmpty() ? List.of() : resolveDomains(domainIds);
        ownerDomainRepository.deleteByOwnerId(user.getId());
        if (!domains.isEmpty()) {
          linkDomains(user, domains);
        }
      } else if (previousRole == OwnerRole.USER) {
        // keep existing links
      }
    }

    Owner saved = ownerRepository.save(user);
    return toResponse(saved);
  }

  public void removeDomain(Long ownerId, Long targetUserId, Long domainId) {
    accessService.requireAdmin(ownerId);
    Owner user = ownerRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));
    if (user.getRole() != OwnerRole.USER) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Only USER can be linked to domains");
    }
    ensureDomainsHaveOtherOwners(user.getId(), List.of(domainId));
    ownerDomainRepository.deleteByOwnerIdAndDomainId(user.getId(), domainId);
  }

  @Transactional
  public void delete(Long ownerId, Long targetUserId) {
    accessService.requireAdmin(ownerId);
    Owner user = ownerRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));
    ensureDomainsHaveOtherOwners(user.getId(), currentDomainIds(user.getId()));
    ownerOtpService.clearAllCodes(user);
    ownerDomainRepository.deleteByOwnerId(user.getId());
    ownerRepository.delete(user);
  }

  private List<Domain> resolveDomains(List<Long> domainIds) {
    List<Domain> domains = domainRepository.findAllById(domainIds);
    if (domains.size() != domainIds.size()) {
      Set<Long> foundIds = domains.stream().map(Domain::getId).collect(Collectors.toSet());
      List<Long> missing = domainIds.stream()
          .filter(id -> !foundIds.contains(id))
          .toList();
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown domain ids: " + missing);
    }
    return domains;
  }

  private void linkDomains(Owner user, List<Domain> domains) {
    List<OwnerDomain> links = new ArrayList<>();
    for (Domain domain : domains) {
      OwnerDomain link = OwnerDomain.builder()
          .owner(user)
          .domain(domain)
          .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
          .build();
      links.add(link);
    }
    ownerDomainRepository.saveAll(links);
  }

  private OwnerResponse toResponse(Owner user) {
    List<Long> domainIds;
    if (user.getRole() == OwnerRole.ADMIN) {
      domainIds = Collections.emptyList();
    } else {
      domainIds = ownerDomainRepository.findByOwnerId(user.getId()).stream()
          .map(link -> link.getDomain().getId())
          .distinct()
          .collect(Collectors.toList());
    }

    return new OwnerResponse(
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
          OwnerRole.USER,
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
}
