package com.userid.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.userid.api.domain.DomainApiTokenResponse;
import com.userid.api.domain.DomainRequest;
import com.userid.api.domain.DomainJwtSecretResponse;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class DomainService {
  private static final Logger log = LoggerFactory.getLogger(DomainService.class);
  private final DomainRepository domainRepository;
  private final OwnerDomainRepository ownerDomainRepository;
  private final OwnerRepository ownerRepository;
  private final AccessService accessService;
  private final DnsAdminClient dnsAdminClient;
  private final DomainJwtSecretService domainJwtSecretService;
  private final DomainApiTokenService domainApiTokenService;
  @org.springframework.beans.factory.annotation.Value("${auth.dns-admin.organization:Org1}")
  private String dnsOrganization;
  @org.springframework.beans.factory.annotation.Value("${auth.dns-admin.server:srv1}")
  private String dnsServer;
  @org.springframework.beans.factory.annotation.Value("${auth.dns-admin.template-server:Server1}")
  private String dnsTemplateServer;

  public DomainResponse create(Long ownerId, DomainRequest request) {
    Owner requester = accessService.requireUser(ownerId);
    log.info("Create domain requested ownerId={} role={} name={}", ownerId, requester.getRole(), request.name());
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
    log.info("Domain created id={} name={}", saved.getId(), saved.getName());
    domainJwtSecretService.getOrCreateSecret(saved);
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
    log.info("Domain ownership linked domainId={} ownerId={}", saved.getId(), requester.getRole() == OwnerRole.ADMIN ? owner.getId() : requester.getId());
    populateDns(saved);
    log.info("Domain DNS populated domainId={}", saved.getId());
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

  public DomainResponse verifyDomain(Long ownerId, Long domainId) {
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
      if (verifyResponse.ok()) {
        domain.setDnsStatus("ok");
        domain.setDnsError(null);
      } else {
        domain.setDnsStatus("error");
        domain.setDnsError(verifyResponse.error());
      }
    } catch (ResponseStatusException ex) {
      domain.setDnsStatus("error");
      domain.setDnsError(ex.getReason());
    }

    return toResponse(domainRepository.save(domain));
  }

  public DomainJwtSecretResponse getUserJwtSecret(Long ownerId, Long domainId) {
    accessService.requireDomainAccess(ownerId, domainId);
    String secret = domainJwtSecretService.getOrCreateSecret(domainId);
    return new DomainJwtSecretResponse(domainId, secret);
  }

  public DomainJwtSecretResponse rotateUserJwtSecret(Long ownerId, Long domainId) {
    accessService.requireDomainAccess(ownerId, domainId);
    String secret = domainJwtSecretService.rotateSecret(domainId);
    return new DomainJwtSecretResponse(domainId, secret);
  }

  public DomainApiTokenResponse generateDomainApiToken(Long ownerId, Long domainId, Long expiresSeconds) {
    accessService.requireDomainAccess(ownerId, domainId);
    return domainApiTokenService.generate(domainId, expiresSeconds);
  }

  @Transactional
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
    boolean verified = Boolean.TRUE.equals(domain.getVerifyStt());
    return new DomainResponse(
        domain.getId(),
        domain.getName(),
        domain.getDnsStatus(),
        domain.getDnsError(),
        domain.getVerify(),
        domain.getVerifyHost(),
        domain.getVerifyType(),
        domain.getVerifyStt(),
        verified ? domain.getSpf() : null,
        verified ? domain.getSpfHost() : null,
        verified ? domain.getSpfType() : null,
        verified ? domain.getSpfStt() : null,
        verified ? domain.getDkim() : null,
        verified ? domain.getDkimHost() : null,
        verified ? domain.getDkimType() : null,
        verified ? domain.getDkimStt() : null,
        verified ? domain.getMx() : null,
        verified ? domain.getMxHost() : null,
        verified ? domain.getMxType() : null,
        verified ? domain.getMxPriority() : null,
        verified ? domain.getMxOptional() : null,
        verified ? domain.getMxStt() : null,
        verified ? domain.getReturnPath() : null,
        verified ? domain.getReturnPathHost() : null,
        verified ? domain.getReturnPathType() : null,
        verified ? domain.getReturnPathStt() : null
    );
  }

  private void populateDns(Domain domain) {
    try {
      log.info("DNS provision start domainId={} name={}", domain.getId(), domain.getName());
      String serverName = buildServerName(domain.getName(), domain.getId(), dnsServer);
      DnsAdminClient.ProvisionResponse response = dnsAdminClient.provisionDomain(
          dnsOrganization,
          dnsTemplateServer,
          serverName,
          domain.getName()
      );
      log.info("DNS provision response domainId={} ok={} error={}", domain.getId(), response.ok(), response.error());
      domain.setDnsStatus(null);
      domain.setDnsError(null);

      if (response.ok() && response.records() != null) {
        JsonNode records = response.records();
        applyRecord(findRecord(records, "verification"), domain::setVerify, domain::setVerifyHost, domain::setVerifyType, null, null, null);
        applyRecord(findRecord(records, "spf"), domain::setSpf, domain::setSpfHost, domain::setSpfType, null, null, null);
        applyRecord(findRecord(records, "dkim"), domain::setDkim, domain::setDkimHost, domain::setDkimType, null, null, null);
        applyRecord(findRecord(records, "return_path"), domain::setReturnPath, domain::setReturnPathHost, domain::setReturnPathType, null, null, null);
        applyRecord(findRecord(records, "mx"), domain::setMx, domain::setMxHost, domain::setMxType, domain::setMxPriority, domain::setMxOptional, null);
        log.info("DNS records saved domainId={}", domain.getId());
      }
      if (response.ok() && response.smtp() != null) {
        String smtpKey = response.smtp().path("key").asText(null);
        if (smtpKey != null && !smtpKey.isBlank()) {
          domain.setSmtpUsername(null);
          domain.setSmtpPassword(smtpKey);
          log.info("SMTP credentials saved domainId={}", domain.getId());
        }
      }
      domain.setVerifyStt(false);
      domain.setSpfStt(false);
      domain.setDkimStt(false);
      domain.setReturnPathStt(false);
      domain.setMxStt(false);
    } catch (ResponseStatusException ex) {
      domain.setDnsStatus("error");
      domain.setDnsError(ex.getReason());
      log.warn("DNS provision failed domainId={} reason={}", domain.getId(), ex.getReason());
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
