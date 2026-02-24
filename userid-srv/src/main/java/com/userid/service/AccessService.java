package com.userid.service;

import com.userid.dal.entity.OwnerEntity;
import com.userid.dal.entity.OwnerRoleEnum;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class AccessService {
  private final OwnerRepository ownerRepository;
  private final OwnerDomainRepository ownerDomainRepository;

  public OwnerEntity requireUser(Long ownerId) {
    if (ownerId == null) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing owner id");
    }
    return ownerRepository.findById(ownerId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Owner not found"));
  }

  public OwnerEntity requireAdmin(Long ownerId) {
    OwnerEntity user = requireUser(ownerId);
    if (user.getRole() != OwnerRoleEnum.ADMIN) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin access required");
    }
    return user;
  }

  public OwnerEntity requireDomainAccess(Long ownerId, Long domainId) {
    OwnerEntity user = requireUser(ownerId);
    if (user.getRole() == OwnerRoleEnum.ADMIN) {
      return user;
    }
    boolean hasAccess = ownerDomainRepository.findByOwnerId(ownerId).stream()
        .anyMatch(link -> link.getDomain() != null && domainId.equals(link.getDomain().getId()));
    if (!hasAccess) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "No access to domain");
    }
    return user;
  }

  public java.util.List<Long> domainIds(Long ownerId) {
    requireUser(ownerId);
    return ownerDomainRepository.findByOwnerId(ownerId).stream()
        .map(link -> link.getDomain().getId())
        .distinct()
        .collect(Collectors.toList());
  }
}
