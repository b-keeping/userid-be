package com.userid.service;

import com.fasterxml.jackson.databind.JsonNode;
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
  private final DnsAdminClient dnsAdminClient;
  @org.springframework.beans.factory.annotation.Value("${auth.dns-admin.organization:Org1}")
  private String dnsOrganization;
  @org.springframework.beans.factory.annotation.Value("${auth.dns-admin.server:srv1}")
  private String dnsServer;
  @org.springframework.beans.factory.annotation.Value("${auth.dns-admin.template-server:Server1}")
  private String dnsTemplateServer;

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
    populateDns(saved);
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

  public DomainResponse checkDns(Long ownerId, Long domainId) {
    accessService.requireDomainAccess(ownerId, domainId);
    Domain domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));

    String serverName = buildServerName(domain.getName(), domain.getId(), dnsServer);
    try {
      DnsAdminClient.VerifyCheckResponse verifyResponse =
          dnsAdminClient.verifyCheck(dnsOrganization, serverName, domain.getName());
      if (verifyResponse.record() != null) {
        applyRecord(
            verifyResponse.record(),
            domain::setVerify,
            domain::setVerifyHost,
            domain::setVerifyType,
            null,
            null,
            domain::setVerifyStt
        );
      }

      DnsAdminClient.DnsCheckResponse dnsResponse =
          dnsAdminClient.dnsCheck(dnsOrganization, serverName, domain.getName());
      JsonNode records = dnsResponse.records();
      applyRecord(findRecord(records, "spf"), domain::setSpf, domain::setSpfHost, domain::setSpfType, null, null, domain::setSpfStt);
      applyRecord(findRecord(records, "dkim"), domain::setDkim, domain::setDkimHost, domain::setDkimType, null, null, domain::setDkimStt);
      applyRecord(findRecord(records, "return_path"), domain::setReturnPath, domain::setReturnPathHost, domain::setReturnPathType, null, null, domain::setReturnPathStt);
      applyRecord(findRecord(records, "mx"), domain::setMx, domain::setMxHost, domain::setMxType, domain::setMxPriority, domain::setMxOptional, domain::setMxStt);

      if (verifyResponse.ok() && dnsResponse.ok()) {
        domain.setDnsStatus("ok");
        domain.setDnsError(null);
      } else {
        domain.setDnsStatus("error");
        domain.setDnsError(firstError(verifyResponse.error(), dnsResponse.error()));
      }
    } catch (ResponseStatusException ex) {
      domain.setDnsStatus("error");
      domain.setDnsError(ex.getReason());
    }

    return toResponse(domainRepository.save(domain));
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
        domain.getDnsStatus(),
        domain.getDnsError(),
        domain.getVerify(),
        domain.getVerifyHost(),
        domain.getVerifyType(),
        domain.getVerifyStt(),
        domain.getSpf(),
        domain.getSpfHost(),
        domain.getSpfType(),
        domain.getSpfStt(),
        domain.getDkim(),
        domain.getDkimHost(),
        domain.getDkimType(),
        domain.getDkimStt(),
        domain.getMx(),
        domain.getMxHost(),
        domain.getMxType(),
        domain.getMxPriority(),
        domain.getMxOptional(),
        domain.getMxStt(),
        domain.getReturnPath(),
        domain.getReturnPathHost(),
        domain.getReturnPathType(),
        domain.getReturnPathStt()
    );
  }

  private void populateDns(Domain domain) {
    try {
      String serverName = buildServerName(domain.getName(), domain.getId(), dnsServer);
      DnsAdminClient.ProvisionResponse response = dnsAdminClient.provisionDomain(
          dnsOrganization,
          dnsTemplateServer,
          serverName,
          domain.getName()
      );
      domain.setDnsStatus(null);
      domain.setDnsError(null);

      if (response.ok() && response.records() != null) {
        JsonNode records = response.records();
        applyRecord(findRecord(records, "verification"), domain::setVerify, domain::setVerifyHost, domain::setVerifyType, null, null, null);
        applyRecord(findRecord(records, "spf"), domain::setSpf, domain::setSpfHost, domain::setSpfType, null, null, null);
        applyRecord(findRecord(records, "dkim"), domain::setDkim, domain::setDkimHost, domain::setDkimType, null, null, null);
        applyRecord(findRecord(records, "return_path"), domain::setReturnPath, domain::setReturnPathHost, domain::setReturnPathType, null, null, null);
        applyRecord(findRecord(records, "mx"), domain::setMx, domain::setMxHost, domain::setMxType, domain::setMxPriority, domain::setMxOptional, null);
      }
      domain.setVerifyStt(false);
      domain.setSpfStt(false);
      domain.setDkimStt(false);
      domain.setReturnPathStt(false);
      domain.setMxStt(false);
    } catch (ResponseStatusException ex) {
      domain.setDnsStatus("error");
      domain.setDnsError(ex.getReason());
    }
  }

  private String buildServerName(String domainName, Long domainId, String fallback) {
    if (domainName != null && !domainName.isBlank()) {
      return domainName;
    }
    if (domainId != null) {
      return "srv-" + domainId;
    }
    return fallback;
  }

  private void applyRecord(
      com.fasterxml.jackson.databind.JsonNode record,
      java.util.function.Consumer<String> valueSetter,
      java.util.function.Consumer<String> hostSetter,
      java.util.function.Consumer<String> typeSetter,
      java.util.function.Consumer<Integer> prioritySetter,
      java.util.function.Consumer<Boolean> optionalSetter,
      java.util.function.Consumer<Boolean> statusSetter
  ) {
    if (record == null || record.isMissingNode()) {
      return;
    }
    if (valueSetter != null) {
      valueSetter.accept(record.path("value").asText(null));
    }
    if (hostSetter != null) {
      hostSetter.accept(record.path("host").asText(null));
    }
    if (typeSetter != null) {
      typeSetter.accept(record.path("type").asText(null));
    }
    if (prioritySetter != null && record.has("priority") && !record.get("priority").isNull()) {
      prioritySetter.accept(record.path("priority").asInt());
    }
    if (optionalSetter != null && record.has("optional") && !record.get("optional").isNull()) {
      optionalSetter.accept(record.path("optional").asBoolean());
    }
    if (statusSetter != null && record.has("ok") && !record.get("ok").isNull()) {
      statusSetter.accept(record.path("ok").asBoolean());
    }
  }

  private com.fasterxml.jackson.databind.JsonNode findRecord(
      com.fasterxml.jackson.databind.JsonNode records,
      String id
  ) {
    if (records == null || !records.isArray()) {
      return null;
    }
    for (com.fasterxml.jackson.databind.JsonNode record : records) {
      if (id.equals(record.path("id").asText(null))) {
        return record;
      }
    }
    return null;
  }

  private String firstError(String primary, String secondary) {
    if (primary != null && !primary.isBlank()) {
      return primary;
    }
    if (secondary != null && !secondary.isBlank()) {
      return secondary;
    }
    return null;
  }
}
