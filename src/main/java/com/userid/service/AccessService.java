package com.userid.service;

import com.userid.dal.entity.Owner;
import com.userid.dal.entity.OwnerRole;
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

  public Owner requireUser(Long ownerId) {
    if (ownerId == null) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing owner id");
    }
    return ownerRepository.findById(ownerId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Owner not found"));
  }

  public Owner requireAdmin(Long ownerId) {
    Owner user = requireUser(ownerId);
    if (user.getRole() != OwnerRole.ADMIN) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin access required");
    }
    return user;
  }

  public Owner requireDomainAccess(Long ownerId, Long domainId) {
    Owner user = requireUser(ownerId);
    if (user.getRole() == OwnerRole.ADMIN) {
      return user;
    }
    boolean hasAccess = ownerDomainRepository.existsByOwnerIdAndDomainId(ownerId, domainId);
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
