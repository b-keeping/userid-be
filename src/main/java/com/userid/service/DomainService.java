package com.userid.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.userid.api.domain.DomainRequest;
import com.userid.api.domain.DomainResponse;
import com.userid.api.domain.DomainUpdateRequest;
import com.userid.dal.entity.Domain;
import com.userid.dal.entity.Owner;
import com.userid.dal.entity.OwnerDomain;
import com.userid.dal.entity.OwnerRole;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
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
  private final OwnerDomainRepository ownerDomainRepository;
  private final OwnerRepository ownerRepository;
  private final AccessService accessService;
  private final PostalAdminClient postalAdminClient;
  private final ObjectMapper objectMapper;
  @org.springframework.beans.factory.annotation.Value("${auth.postal-admin.organization:Org1}")
  private String postalOrganization;
  @org.springframework.beans.factory.annotation.Value("${auth.postal-admin.server:srv1}")
  private String postalServer;
  @org.springframework.beans.factory.annotation.Value("${auth.postal-admin.template-server:Server1}")
  private String postalTemplateServer;
  @org.springframework.beans.factory.annotation.Value("${auth.postal-admin.smtp-name:SMTP}")
  private String postalSmtpName;
  @org.springframework.beans.factory.annotation.Value("${auth.postal-admin.smtp-hold:false}")
  private boolean postalSmtpHold;

  public DomainResponse create(Long ownerId, DomainRequest request) {
    Owner requester = accessService.requireUser(ownerId);
    if (requester.getRole() != OwnerRole.ADMIN && request.ownerId() != null) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Owner can be set only by admin");
    }

    Owner owner = null;
    if (requester.getRole() == OwnerRole.ADMIN) {
      Long targetOwnerId = request.ownerId();
      if (targetOwnerId == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Owner is required for admin");
      }
      owner = ownerRepository.findById(targetOwnerId)
          .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));
      if (owner.getRole() != OwnerRole.USER) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Owner must be USER");
      }
    }

    Domain domain = Domain.builder()
        .name(request.name())
        .build();

    Domain saved = domainRepository.save(domain);
    if (requester.getRole() == OwnerRole.ADMIN) {
      if (ownerDomainRepository.existsByDomainId(saved.getId())) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Domain already has owner");
      }
      linkDomain(owner, saved);
    } else {
      if (ownerDomainRepository.existsByDomainId(saved.getId())) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Domain already has owner");
      }
      linkDomain(requester, saved);
    }
    populatePostal(saved);
    return toResponse(domainRepository.save(saved));
  }

  public List<DomainResponse> list(Long ownerId) {
    var user = accessService.requireUser(ownerId);
    if (user.getRole() == OwnerRole.ADMIN) {
      return domainRepository.findAll().stream()
          .map(this::toResponse)
          .collect(Collectors.toList());
    }

    List<Long> domainIds = accessService.domainIds(ownerId);
    if (domainIds.isEmpty()) {
      return List.of();
    }
    return domainRepository.findAllById(domainIds).stream()
        .map(this::toResponse)
        .collect(Collectors.toList());
  }

  public DomainResponse update(Long ownerId, Long domainId, DomainUpdateRequest request) {
    accessService.requireDomainAccess(ownerId, domainId);
    Domain domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    if (request.name() != null && !request.name().isBlank()) {
      domain.setName(request.name());
    }

    Domain saved = domainRepository.save(domain);
    return toResponse(saved);
  }

  public void delete(Long ownerId, Long domainId) {
    accessService.requireDomainAccess(ownerId, domainId);
    if (!domainRepository.existsById(domainId)) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found");
    }
    ownerDomainRepository.deleteByDomainId(domainId);
    domainRepository.deleteById(domainId);
  }

  private void linkDomain(Owner user, Domain domain) {
    if (ownerDomainRepository.existsByOwnerIdAndDomainId(user.getId(), domain.getId())) {
      return;
    }
    OwnerDomain link = OwnerDomain.builder()
        .owner(user)
        .domain(domain)
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();
    ownerDomainRepository.save(link);
  }


  private DomainResponse toResponse(Domain domain) {
    return new DomainResponse(
        domain.getId(),
        domain.getName(),
        domain.getPostalStatus(),
        domain.getPostalError(),
        domain.getPostalDomainJsonb(),
        domain.getPostalDnsRecordsJsonb(),
        domain.getPostalDnsCheckJsonb(),
        domain.getPostalVerificationJsonb(),
        domain.getPostalSpfJsonb(),
        domain.getPostalDkimJsonb(),
        domain.getPostalReturnPathJsonb(),
        domain.getPostalMxJsonb()
    );
  }

  private void populatePostal(Domain domain) {
    try {
      String serverName = buildPostalServerName(domain.getName(), domain.getId(), postalServer);
      PostalAdminClient.PostalAdminResponse response = postalAdminClient.provisionDomain(
          postalOrganization,
          postalTemplateServer,
          serverName,
          domain.getName(),
          postalSmtpName,
          postalSmtpHold
      );
      domain.setPostalStatus(response.ok() ? "ok" : "error");
      domain.setPostalError(response.error());
      domain.setPostalDomainJsonb(response.domain());
      domain.setPostalDnsRecordsJsonb(response.dnsRecords());
      domain.setPostalDnsCheckJsonb(response.dnsCheck());
      domain.setPostalVerificationJsonb(buildPostalPurpose("verification", response.dnsRecords(), response.dnsCheck()));
      domain.setPostalSpfJsonb(buildPostalPurpose("spf", response.dnsRecords(), response.dnsCheck()));
      domain.setPostalDkimJsonb(buildPostalPurpose("dkim", response.dnsRecords(), response.dnsCheck()));
      domain.setPostalReturnPathJsonb(buildPostalPurpose("return_path", response.dnsRecords(), response.dnsCheck()));
      domain.setPostalMxJsonb(buildPostalPurpose("mx", response.dnsRecords(), response.dnsCheck()));
    } catch (ResponseStatusException ex) {
      domain.setPostalStatus("error");
      domain.setPostalError(ex.getReason());
    }
  }

  private String buildPostalServerName(String domainName, Long domainId, String fallback) {
    if (domainName != null && !domainName.isBlank()) {
      return domainName;
    }
    if (domainId != null) {
      return "srv-" + domainId;
    }
    return fallback;
  }

  private JsonNode buildPostalPurpose(String purpose, JsonNode dnsRecords, JsonNode dnsCheck) {
    ObjectNode node = objectMapper.createObjectNode();
    ArrayNode records = objectMapper.createArrayNode();
    ArrayNode checks = objectMapper.createArrayNode();

    if (dnsRecords != null && dnsRecords.isArray()) {
      for (JsonNode record : dnsRecords) {
        if (purpose.equals(record.path("purpose").asText(null))) {
          records.add(record);
        }
      }
    }

    if (dnsCheck != null && dnsCheck.has("checks") && dnsCheck.get("checks").isArray()) {
      for (JsonNode check : dnsCheck.get("checks")) {
        if (purpose.equals(check.path("purpose").asText(null))) {
          checks.add(check);
        }
      }
    }

    node.set("records", records);
    node.set("checks", checks);

    if (checks.size() > 0) {
      boolean allOk = true;
      boolean allOptional = true;
      for (JsonNode check : checks) {
        if (!check.path("ok").asBoolean(false)) {
          allOk = false;
        }
        if (!check.path("optional").asBoolean(false)) {
          allOptional = false;
        }
      }
      node.put("ok", allOk);
      node.put("optional", allOptional);
    }

    return node;
  }
}
