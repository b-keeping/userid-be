package com.userid.service;

import com.userid.api.domain.DomainRequest;
import com.userid.api.domain.DomainResponse;
import com.userid.api.domain.DomainUpdateRequest;
import com.userid.dal.entity.Domain;
import com.userid.dal.entity.ServiceUserRole;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.ServiceUserDomainRepository;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class DomainService {
  private final DomainRepository domainRepository;
  private final ServiceUserDomainRepository serviceUserDomainRepository;
  private final AccessService accessService;

  public DomainResponse create(Long serviceUserId, DomainRequest request) {
    accessService.requireAdmin(serviceUserId);
    domainRepository.findByCode(request.code())
        .ifPresent(domain -> {
          throw new ResponseStatusException(HttpStatus.CONFLICT, "Domain code already exists");
        });

    Domain domain = Domain.builder()
        .code(request.code())
        .name(request.name())
        .build();

    Domain saved = domainRepository.save(domain);
    return toResponse(saved);
  }

  public List<DomainResponse> list(Long serviceUserId) {
    var user = accessService.requireUser(serviceUserId);
    if (user.getRole() == ServiceUserRole.ADMIN) {
      return domainRepository.findAll().stream()
          .map(this::toResponse)
          .collect(Collectors.toList());
    }

    List<Long> domainIds = accessService.domainIds(serviceUserId);
    if (domainIds.isEmpty()) {
      return List.of();
    }
    return domainRepository.findAllById(domainIds).stream()
        .map(this::toResponse)
        .collect(Collectors.toList());
  }

  public DomainResponse update(Long serviceUserId, Long domainId, DomainUpdateRequest request) {
    accessService.requireAdmin(serviceUserId);
    Domain domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));

    if (request.code() != null && !request.code().isBlank()) {
      if (!request.code().equals(domain.getCode()) && domainRepository.findByCode(request.code()).isPresent()) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Domain code already exists");
      }
      domain.setCode(request.code());
    }

    if (request.name() != null && !request.name().isBlank()) {
      domain.setName(request.name());
    }

    Domain saved = domainRepository.save(domain);
    return toResponse(saved);
  }

  public void delete(Long serviceUserId, Long domainId) {
    accessService.requireAdmin(serviceUserId);
    if (!domainRepository.existsById(domainId)) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found");
    }
    serviceUserDomainRepository.deleteByDomainId(domainId);
    domainRepository.deleteById(domainId);
  }

  private DomainResponse toResponse(Domain domain) {
    return new DomainResponse(domain.getId(), domain.getCode(), domain.getName());
  }
}
