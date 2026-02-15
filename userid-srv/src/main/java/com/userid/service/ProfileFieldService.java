package com.userid.service;

import com.userid.api.domain.ProfileFieldRequest;
import com.userid.api.domain.ProfileFieldResponse;
import com.userid.api.domain.ProfileFieldUpdateRequest;
import com.userid.dal.entity.Domain;
import com.userid.dal.entity.ProfileField;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.ProfileFieldRepository;
import com.userid.dal.repo.UserProfileValueRepository;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class ProfileFieldService {
  private final DomainRepository domainRepository;
  private final ProfileFieldRepository profileFieldRepository;
  private final UserProfileValueRepository userProfileValueRepository;
  private final AccessService accessService;

  public ProfileFieldResponse create(Long serviceUserId, Long domainId, ProfileFieldRequest request) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    Domain domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));

    profileFieldRepository.findByDomainIdAndName(domainId, request.name())
        .ifPresent(field -> {
          throw new ResponseStatusException(HttpStatus.CONFLICT, "Field name already exists for domain");
        });

    ProfileField field = ProfileField.builder()
        .domain(domain)
        .name(request.name())
        .type(request.type())
        .mandatory(Boolean.TRUE.equals(request.mandatory()))
        .sortOrder(request.sortOrder())
        .build();

    ProfileField saved = profileFieldRepository.save(field);
    return toResponse(saved);
  }

  public List<ProfileFieldResponse> list(Long serviceUserId, Long domainId) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    if (!domainRepository.existsById(domainId)) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found");
    }
    List<ProfileField> fields = profileFieldRepository.findByDomainId(domainId);
    return fields.stream()
        .sorted(Comparator
            .comparing(ProfileField::getSortOrder, Comparator.nullsLast(Integer::compareTo))
            .thenComparing(ProfileField::getId))
        .map(this::toResponse)
        .collect(Collectors.toList());
  }

  public ProfileFieldResponse update(
      Long serviceUserId,
      Long domainId,
      Long fieldId,
      ProfileFieldUpdateRequest request
  ) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    ProfileField field = profileFieldRepository.findByIdAndDomainId(fieldId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Profile field not found"));

    if (request.name() != null && !request.name().isBlank() && !request.name().equals(field.getName())) {
      profileFieldRepository.findByDomainIdAndName(domainId, request.name())
          .ifPresent(existing -> {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Field name already exists for domain");
          });
      field.setName(request.name());
    }

    if (request.type() != null && request.type() != field.getType()) {
      long existingValues = userProfileValueRepository.countByFieldId(fieldId);
      if (existingValues > 0) {
        throw new ResponseStatusException(
            HttpStatus.CONFLICT,
            "Cannot change type when values exist"
        );
      }
      field.setType(request.type());
    }

    if (request.mandatory() != null) {
      field.setMandatory(request.mandatory());
    }
    if (request.sortOrder() != null) {
      field.setSortOrder(request.sortOrder());
    }

    ProfileField saved = profileFieldRepository.save(field);
    return toResponse(saved);
  }

  @Transactional
  public void delete(Long serviceUserId, Long domainId, Long fieldId) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    ProfileField field = profileFieldRepository.findByIdAndDomainId(fieldId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Profile field not found"));
    userProfileValueRepository.deleteByFieldId(field.getId());
    profileFieldRepository.delete(field);
  }

  private ProfileFieldResponse toResponse(ProfileField field) {
    return new ProfileFieldResponse(
        field.getId(),
        field.getName(),
        field.getType(),
        field.isMandatory(),
        field.getSortOrder()
    );
  }
}
