package com.userid.service;

import com.userid.api.domain.ProfileFieldRequestDTO;
import com.userid.api.domain.ProfileFieldResponseDTO;
import com.userid.api.domain.ProfileFieldUpdateRequestDTO;
import com.userid.dal.entity.DomainEntity;
import com.userid.dal.entity.ProfileFieldEntity;
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

  public ProfileFieldResponseDTO create(Long serviceUserId, Long domainId, ProfileFieldRequestDTO request) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));

    profileFieldRepository.findByDomainIdAndName(domainId, request.name())
        .ifPresent(field -> {
          throw new ResponseStatusException(HttpStatus.CONFLICT, "Field name already exists for domain");
        });

    ProfileFieldEntity field = ProfileFieldEntity.builder()
        .domain(domain)
        .name(request.name())
        .type(request.type())
        .mandatory(Boolean.TRUE.equals(request.mandatory()))
        .sortOrder(request.sortOrder())
        .build();

    ProfileFieldEntity saved = profileFieldRepository.save(field);
    return toResponse(saved);
  }

  public List<ProfileFieldResponseDTO> list(Long serviceUserId, Long domainId) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    if (!domainRepository.existsById(domainId)) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found");
    }
    List<ProfileFieldEntity> fields = profileFieldRepository.findByDomainId(domainId);
    return fields.stream()
        .sorted(Comparator
            .comparing(ProfileFieldEntity::getSortOrder, Comparator.nullsLast(Integer::compareTo))
            .thenComparing(ProfileFieldEntity::getId))
        .map(this::toResponse)
        .collect(Collectors.toList());
  }

  public ProfileFieldResponseDTO update(
      Long serviceUserId,
      Long domainId,
      Long fieldId,
      ProfileFieldUpdateRequestDTO request
  ) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    ProfileFieldEntity field = profileFieldRepository.findByIdAndDomainId(fieldId, domainId)
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

    ProfileFieldEntity saved = profileFieldRepository.save(field);
    return toResponse(saved);
  }

  @Transactional
  public void delete(Long serviceUserId, Long domainId, Long fieldId) {
    accessService.requireDomainAccess(serviceUserId, domainId);
    ProfileFieldEntity field = profileFieldRepository.findByIdAndDomainId(fieldId, domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Profile field not found"));
    userProfileValueRepository.deleteByFieldId(field.getId());
    profileFieldRepository.delete(field);
  }

  private ProfileFieldResponseDTO toResponse(ProfileFieldEntity field) {
    return new ProfileFieldResponseDTO(
        field.getId(),
        field.getName(),
        field.getType(),
        field.isMandatory(),
        field.getSortOrder()
    );
  }
}
