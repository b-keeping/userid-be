package com.userid.service;

import com.userid.api.serviceuser.ServiceUserDomainRequest;
import com.userid.api.serviceuser.ServiceUserRequest;
import com.userid.api.serviceuser.ServiceUserResponse;
import com.userid.api.serviceuser.ServiceUserUpdateRequest;
import com.userid.dal.entity.Domain;
import com.userid.dal.entity.ServiceUser;
import com.userid.dal.entity.ServiceUserDomain;
import com.userid.dal.entity.ServiceUserRole;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.ServiceUserDomainRepository;
import com.userid.dal.repo.ServiceUserRepository;
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
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class ServiceUserService {
  private final ServiceUserRepository serviceUserRepository;
  private final ServiceUserDomainRepository serviceUserDomainRepository;
  private final DomainRepository domainRepository;
  private final AccessService accessService;
  private final PasswordEncoder passwordEncoder;

  public ServiceUserResponse create(Long serviceUserId, ServiceUserRequest request) {
    accessService.requireAdmin(serviceUserId);

    serviceUserRepository.findByUsername(request.username())
        .ifPresent(user -> {
          throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists");
        });

    List<Long> domainIds = request.domainIds() == null ? List.of() : request.domainIds();
    List<Domain> domains = List.of();
    if (request.role() == ServiceUserRole.USER) {
      if (domainIds.isEmpty()) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "USER must be linked to at least one domain");
      }
      domains = resolveDomains(domainIds);
    }

    String password = requirePassword(request.password());

    ServiceUser user = ServiceUser.builder()
        .username(request.username())
        .passwordHash(passwordEncoder.encode(password))
        .role(request.role())
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();

    ServiceUser saved = serviceUserRepository.save(user);

    if (request.role() == ServiceUserRole.USER) {
      linkDomains(saved, domains);
    }

    return toResponse(saved);
  }

  public List<ServiceUserResponse> list(Long serviceUserId) {
    accessService.requireAdmin(serviceUserId);
    return serviceUserRepository.findAll().stream()
        .map(this::toResponse)
        .collect(Collectors.toList());
  }

  public ServiceUserResponse get(Long serviceUserId, Long targetUserId) {
    ServiceUser requester = accessService.requireUser(serviceUserId);
    if (requester.getRole() != ServiceUserRole.ADMIN && !requester.getId().equals(targetUserId)) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
    }
    ServiceUser user = serviceUserRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Service user not found"));
    return toResponse(user);
  }

  public ServiceUserResponse addDomain(Long serviceUserId, Long targetUserId, ServiceUserDomainRequest request) {
    accessService.requireAdmin(serviceUserId);

    ServiceUser user = serviceUserRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Service user not found"));

    if (user.getRole() != ServiceUserRole.USER) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Only USER can be linked to domains");
    }

    Long domainId = request.domainId();
    Domain domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));

    if (!serviceUserDomainRepository.existsByServiceUserIdAndDomainId(user.getId(), domainId)) {
      ServiceUserDomain link = ServiceUserDomain.builder()
          .serviceUser(user)
          .domain(domain)
          .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
          .build();
      serviceUserDomainRepository.save(link);
    }

    return toResponse(user);
  }

  public ServiceUserResponse update(Long serviceUserId, Long targetUserId, ServiceUserUpdateRequest request) {
    accessService.requireAdmin(serviceUserId);
    ServiceUser user = serviceUserRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Service user not found"));

    if (request.username() != null && !request.username().isBlank()
        && !request.username().equals(user.getUsername())) {
      if (serviceUserRepository.existsByUsername(request.username())) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists");
      }
      user.setUsername(request.username());
    }

    if (request.password() != null && !request.password().isBlank()) {
      user.setPasswordHash(passwordEncoder.encode(request.password()));
    }

    ServiceUserRole previousRole = user.getRole();
    ServiceUserRole targetRole = request.role() != null ? request.role() : previousRole;
    user.setRole(targetRole);

    if (targetRole == ServiceUserRole.ADMIN) {
      serviceUserDomainRepository.deleteByServiceUserId(user.getId());
    } else {
      List<Long> domainIds = request.domainIds();
      if (domainIds != null) {
        if (domainIds.isEmpty()) {
          throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "USER must be linked to at least one domain");
        }
        List<Domain> domains = resolveDomains(domainIds);
        serviceUserDomainRepository.deleteByServiceUserId(user.getId());
        linkDomains(user, domains);
      } else if (previousRole == ServiceUserRole.USER) {
        // keep existing links
      } else if (previousRole == ServiceUserRole.ADMIN) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "USER must be linked to at least one domain");
      }
    }

    ServiceUser saved = serviceUserRepository.save(user);
    return toResponse(saved);
  }

  public void removeDomain(Long serviceUserId, Long targetUserId, Long domainId) {
    accessService.requireAdmin(serviceUserId);
    ServiceUser user = serviceUserRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Service user not found"));
    if (user.getRole() != ServiceUserRole.USER) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Only USER can be linked to domains");
    }
    serviceUserDomainRepository.deleteByServiceUserIdAndDomainId(user.getId(), domainId);
  }

  public void delete(Long serviceUserId, Long targetUserId) {
    accessService.requireAdmin(serviceUserId);
    ServiceUser user = serviceUserRepository.findById(targetUserId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Service user not found"));
    serviceUserDomainRepository.deleteByServiceUserId(user.getId());
    serviceUserRepository.delete(user);
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

  private void linkDomains(ServiceUser user, List<Domain> domains) {
    List<ServiceUserDomain> links = new ArrayList<>();
    for (Domain domain : domains) {
      ServiceUserDomain link = ServiceUserDomain.builder()
          .serviceUser(user)
          .domain(domain)
          .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
          .build();
      links.add(link);
    }
    serviceUserDomainRepository.saveAll(links);
  }

  private ServiceUserResponse toResponse(ServiceUser user) {
    List<Long> domainIds;
    if (user.getRole() == ServiceUserRole.ADMIN) {
      domainIds = Collections.emptyList();
    } else {
      domainIds = serviceUserDomainRepository.findByServiceUserId(user.getId()).stream()
          .map(link -> link.getDomain().getId())
          .distinct()
          .toList();
    }

    return new ServiceUserResponse(
        user.getId(),
        user.getUsername(),
        user.getRole(),
        user.getCreatedAt(),
        domainIds
    );
  }

  private static String requirePassword(String password) {
    if (password == null || password.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required");
    }
    return password;
  }
}
