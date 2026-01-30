package com.userid.service;

import com.userid.dal.entity.ServiceUser;
import com.userid.dal.entity.ServiceUserRole;
import com.userid.dal.repo.ServiceUserDomainRepository;
import com.userid.dal.repo.ServiceUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class AccessService {
  private final ServiceUserRepository serviceUserRepository;
  private final ServiceUserDomainRepository serviceUserDomainRepository;

  public ServiceUser requireUser(Long serviceUserId) {
    if (serviceUserId == null) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing service user id");
    }
    return serviceUserRepository.findById(serviceUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Service user not found"));
  }

  public ServiceUser requireAdmin(Long serviceUserId) {
    ServiceUser user = requireUser(serviceUserId);
    if (user.getRole() != ServiceUserRole.ADMIN) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin access required");
    }
    return user;
  }

  public ServiceUser requireDomainAccess(Long serviceUserId, Long domainId) {
    ServiceUser user = requireUser(serviceUserId);
    if (user.getRole() == ServiceUserRole.ADMIN) {
      return user;
    }
    boolean hasAccess = serviceUserDomainRepository.existsByServiceUserIdAndDomainId(serviceUserId, domainId);
    if (!hasAccess) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "No access to domain");
    }
    return user;
  }

  public java.util.List<Long> domainIds(Long serviceUserId) {
    requireUser(serviceUserId);
    return serviceUserDomainRepository.findByServiceUserId(serviceUserId).stream()
        .map(link -> link.getDomain().getId())
        .distinct()
        .toList();
  }
}
