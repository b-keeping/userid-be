package com.userid.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.userid.api.domain.DomainApiTokenResponseDTO;
import com.userid.api.domain.DomainRequestDTO;
import com.userid.api.domain.DomainJwtSecretResponseDTO;
import com.userid.api.domain.DomainResponseDTO;
import com.userid.api.domain.DomainUpdateRequestDTO;
import com.userid.dal.entity.DomainEntity;
import com.userid.dal.entity.OwnerEntity;
import com.userid.dal.entity.OwnerDomainEntity;
import com.userid.dal.entity.OwnerRoleEnum;
import com.userid.dal.repo.DomainRepository;
import com.userid.dal.repo.DomainSocialProviderConfigRepository;
import com.userid.dal.repo.OwnerDomainRepository;
import com.userid.dal.repo.OwnerRepository;
import com.userid.dal.repo.UserSocialIdentityRepository;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
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
  private static final String PSRP_HOST_PREFIX = "psrp.";
  private static final String DEFAULT_RETURN_PATH_SPF = "v=spf1 a:post.userid.sh -all";
  private final DomainRepository domainRepository;
  private final DomainSocialProviderConfigRepository domainSocialProviderConfigRepository;
  private final OwnerDomainRepository ownerDomainRepository;
  private final OwnerRepository ownerRepository;
  private final UserSocialIdentityRepository userSocialIdentityRepository;
  private final AccessService accessService;
  private final PostalAdminClient postalAdminClient;
  private final DnsLookupService dnsLookupService;
  private final DomainJwtSecretService domainJwtSecretService;
  private final DomainApiTokenService domainApiTokenService;
  @org.springframework.beans.factory.annotation.Value("${auth.postal-admin.organization:Org1}")
  private String postalOrganization;
  @org.springframework.beans.factory.annotation.Value("${auth.postal-admin.template-server:Server1}")
  private String postalTemplateServer;
  @org.springframework.beans.factory.annotation.Value("${auth.postal-admin.smtp-name:}")
  private String postalSmtpName;
  @org.springframework.beans.factory.annotation.Value("${auth.postal-admin.return-path-spf:v=spf1 a:post.userid.sh -all}")
  private String postalReturnPathSpf;

  public DomainResponseDTO create(Long ownerId, DomainRequestDTO request) {
    OwnerEntity requester = accessService.requireUser(ownerId);
    log.info("Create domain requested ownerId={} role={} name={}", ownerId, requester.getRole(), request.name());
    if (requester.getRole() != OwnerRoleEnum.ADMIN && request.ownerId() != null) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Owner can be set only by admin");
    }

    OwnerEntity owner = null;
    if (requester.getRole() == OwnerRoleEnum.ADMIN) {
      Long targetOwnerId = request.ownerId();
      if (targetOwnerId == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Owner is required for admin");
      }
      owner = ownerRepository.findById(targetOwnerId)
          .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner not found"));
      if (owner.getRole() != OwnerRoleEnum.USER) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Owner must be USER");
      }
    }

    DomainEntity domain = DomainEntity.builder()
        .name(request.name())
        .build();

    DomainEntity saved = domainRepository.save(domain);
    log.info("Domain created id={} name={}", saved.getId(), saved.getName());
    domainJwtSecretService.getOrCreateSecret(saved);
    if (requester.getRole() == OwnerRoleEnum.ADMIN) {
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
    log.info("Domain ownership linked domainId={} ownerId={}", saved.getId(), requester.getRole() == OwnerRoleEnum.ADMIN ? owner==null?null:owner.getId() : requester.getId());
    populateDns(saved, false);
    log.info("Domain DNS populated domainId={}", saved.getId());
    return toResponse(domainRepository.save(saved));
  }

  public List<DomainResponseDTO> list(Long ownerId) {
    var user = accessService.requireUser(ownerId);
    if (user.getRole() == OwnerRoleEnum.ADMIN) {
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

  public DomainResponseDTO update(Long ownerId, Long domainId, DomainUpdateRequestDTO request) {
    accessService.requireDomainAccess(ownerId, domainId);
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    if (request.name() != null && !request.name().isBlank()) {
      domain.setName(request.name());
    }

    DomainEntity saved = domainRepository.save(domain);
    return toResponse(saved);
  }

  public DomainResponseDTO checkDns(Long ownerId, Long domainId) {
    accessService.requireDomainAccess(ownerId, domainId);
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));

    String serverName = buildServerName(domain.getName());
    boolean psrpOk = false;
    try {
      PostalAdminClient.VerifyCheckResponseDTO verifyResponse =
          postalAdminClient.verifyCheck(postalOrganization, serverName, domain.getName());
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

      PostalAdminClient.DnsCheckResponseDTO dnsResponse =
          postalAdminClient.dnsCheck(postalOrganization, serverName, domain.getName());
      JsonNode records = dnsResponse.records();
      applyRecord(findRecord(records, "spf"), domain::setSpf, domain::setSpfHost, domain::setSpfType, null, null, domain::setSpfStt);
      applyRecord(findRecord(records, "dkim"), domain::setDkim, domain::setDkimHost, domain::setDkimType, null, null, domain::setDkimStt);
      applyRecord(findRecord(records, "mx"), domain::setMx, domain::setMxHost, domain::setMxType, domain::setMxPriority, domain::setMxOptional, domain::setMxStt);
      String returnPathSpf = returnPathSpfValue();
      domain.setReturnPath(returnPathSpf);
      domain.setReturnPathHost(psrpHost(domain.getName()));
      domain.setReturnPathType("TXT");

      boolean spfOk = requiredRecordOk(records, "spf");
      boolean dkimOk = requiredRecordOk(records, "dkim");
      boolean mxOk = requiredRecordOk(records, "mx");
      psrpOk = dnsLookupService.hasTxtRecord(psrpHost(domain.getName()), returnPathSpf);
      domain.setReturnPathStt(psrpOk);

      String error = null;
      if (!verifyResponse.ok()) {
        error = appendError(error, firstError(verifyResponse.error(), "Domain verification check failed"));
      }
      if (verifyResponse.ok() && records == null && !dnsResponse.ok()) {
        error = appendError(error, firstError(dnsResponse.error(), "DNS check failed"));
      }
      if (verifyResponse.ok()) {
        if (!spfOk) {
          error = appendError(error, "SPF record is not valid");
        }
        if (!dkimOk) {
          error = appendError(error, "DKIM record is not valid");
        }
        if (!mxOk) {
          error = appendError(error, "MX record is not valid");
        }
        if (!psrpOk) {
          error = appendError(error, returnPathMissingError(domain.getName()));
        }
      }

      if (error == null) {
        domain.setDnsStatus("ok");
        domain.setDnsError(null);
      } else {
        domain.setDnsStatus("error");
        domain.setDnsError(error);
      }
    } catch (ResponseStatusException ex) {
      domain.setDnsStatus("error");
      domain.setDnsError(ex.getReason());
      String returnPathSpf = returnPathSpfValue();
      psrpOk = dnsLookupService.hasTxtRecord(psrpHost(domain.getName()), returnPathSpf);
      domain.setReturnPath(returnPathSpf);
      domain.setReturnPathHost(psrpHost(domain.getName()));
      domain.setReturnPathType("TXT");
      domain.setReturnPathStt(psrpOk);
      if (!psrpOk) {
        domain.setDnsError(appendError(domain.getDnsError(), returnPathMissingError(domain.getName())));
      }
    }

    return toResponse(domainRepository.save(domain));
  }

  public DomainResponseDTO resetSmtp(Long ownerId, Long domainId) {
    accessService.requireDomainAccess(ownerId, domainId);
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    populateDns(domain, true);
    return toResponse(domainRepository.save(domain));
  }

  public DomainResponseDTO verifyDomain(Long ownerId, Long domainId) {
    accessService.requireDomainAccess(ownerId, domainId);
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));

    String serverName = buildServerName(domain.getName());
    try {
      PostalAdminClient.VerifyCheckResponseDTO verifyResponse =
          postalAdminClient.verifyCheck(postalOrganization, serverName, domain.getName());
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

  public DomainJwtSecretResponseDTO getUserJwtSecret(Long ownerId, Long domainId) {
    accessService.requireDomainAccess(ownerId, domainId);
    String secret = domainJwtSecretService.getOrCreateSecret(domainId);
    return new DomainJwtSecretResponseDTO(domainId, secret);
  }

  public DomainJwtSecretResponseDTO rotateUserJwtSecret(Long ownerId, Long domainId) {
    accessService.requireDomainAccess(ownerId, domainId);
    String secret = domainJwtSecretService.rotateSecret(domainId);
    return new DomainJwtSecretResponseDTO(domainId, secret);
  }

  public DomainApiTokenResponseDTO generateDomainApiToken(Long ownerId, Long domainId, Long expiresSeconds) {
    accessService.requireDomainAccess(ownerId, domainId);
    return domainApiTokenService.generate(domainId, expiresSeconds);
  }

  @Transactional
  public void delete(Long ownerId, Long domainId) {
    accessService.requireDomainAccess(ownerId, domainId);
    DomainEntity domain = domainRepository.findById(domainId)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Domain not found"));
    userSocialIdentityRepository.deleteByDomainId(domainId);
    domainSocialProviderConfigRepository.deleteByDomainId(domainId);
    ownerDomainRepository.deleteByDomainId(domainId);
    domainRepository.delete(domain);
  }

  private void linkDomain(OwnerEntity user, DomainEntity domain) {
    if (ownerDomainRepository.existsByOwnerIdAndDomainId(user.getId(), domain.getId())) {
      return;
    }
    OwnerDomainEntity link = OwnerDomainEntity.builder()
        .owner(user)
        .domain(domain)
        .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
        .build();
    ownerDomainRepository.save(link);
  }


  private DomainResponseDTO toResponse(DomainEntity domain) {
    boolean verified = Boolean.TRUE.equals(domain.getVerifyStt());
    return new DomainResponseDTO(
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

  private void populateDns(DomainEntity domain, boolean preserveStatusesOnSame) {
    try {
      log.info("DNS provision start domainId={} name={}", domain.getId(), domain.getName());
      String serverName = buildServerName(domain.getName());
      PostalAdminClient.ProvisionResponseDTO response = postalAdminClient.provisionDomain(
          postalOrganization,
          postalTemplateServer,
          serverName,
          domain.getName(),
          postalSmtpName
      );
      log.info("DNS provision response domainId={} ok={} error={}", domain.getId(), response.ok(), response.error());
      if (response.ok()) {
        domain.setDnsStatus(null);
        domain.setDnsError(null);
      } else {
        domain.setDnsStatus("error");
        domain.setDnsError(firstError(response.error(), "Domain provisioning failed"));
      }

      if (response.ok() && response.records() != null) {
        JsonNode records = response.records();
        if (preserveStatusesOnSame) {
          boolean changedVerify = applyRecordIfChanged(
              findRecord(records, "verification"),
              domain.getVerify(),
              domain.getVerifyHost(),
              domain.getVerifyType(),
              null,
              null,
              domain::setVerify,
              domain::setVerifyHost,
              domain::setVerifyType,
              null,
              null
          );
          if (changedVerify) {
            domain.setVerifyStt(false);
          }
          boolean changedSpf = applyRecordIfChanged(
              findRecord(records, "spf"),
              domain.getSpf(),
              domain.getSpfHost(),
              domain.getSpfType(),
              null,
              null,
              domain::setSpf,
              domain::setSpfHost,
              domain::setSpfType,
              null,
              null
          );
          if (changedSpf) {
            domain.setSpfStt(false);
          }
          boolean changedDkim = applyRecordIfChanged(
              findRecord(records, "dkim"),
              domain.getDkim(),
              domain.getDkimHost(),
              domain.getDkimType(),
              null,
              null,
              domain::setDkim,
              domain::setDkimHost,
              domain::setDkimType,
              null,
              null
          );
          if (changedDkim) {
            domain.setDkimStt(false);
          }
          String returnPathSpf = returnPathSpfValue();
          boolean changedReturnPath = !Objects.equals(domain.getReturnPath(), returnPathSpf)
              || !Objects.equals(domain.getReturnPathHost(), psrpHost(domain.getName()))
              || !Objects.equals(domain.getReturnPathType(), "TXT");
          domain.setReturnPath(returnPathSpf);
          domain.setReturnPathHost(psrpHost(domain.getName()));
          domain.setReturnPathType("TXT");
          if (changedReturnPath) {
            domain.setReturnPathStt(false);
          }
          boolean changedMx = applyRecordIfChanged(
              findRecord(records, "mx"),
              domain.getMx(),
              domain.getMxHost(),
              domain.getMxType(),
              domain.getMxPriority(),
              domain.getMxOptional(),
              domain::setMx,
              domain::setMxHost,
              domain::setMxType,
              domain::setMxPriority,
              domain::setMxOptional
          );
          if (changedMx) {
            domain.setMxStt(false);
          }
        } else {
          applyRecord(findRecord(records, "verification"), domain::setVerify, domain::setVerifyHost, domain::setVerifyType, null, null, null);
          applyRecord(findRecord(records, "spf"), domain::setSpf, domain::setSpfHost, domain::setSpfType, null, null, null);
          applyRecord(findRecord(records, "dkim"), domain::setDkim, domain::setDkimHost, domain::setDkimType, null, null, null);
          domain.setReturnPath(returnPathSpfValue());
          domain.setReturnPathHost(psrpHost(domain.getName()));
          domain.setReturnPathType("TXT");
          applyRecord(findRecord(records, "mx"), domain::setMx, domain::setMxHost, domain::setMxType, domain::setMxPriority, domain::setMxOptional, null);
          domain.setVerifyStt(false);
          domain.setSpfStt(false);
          domain.setDkimStt(false);
          domain.setReturnPathStt(false);
          domain.setMxStt(false);
        }
        log.info("DNS records saved domainId={}", domain.getId());
      }
      if (response.ok() && response.smtp() != null) {
        String smtpKey = response.smtp().path("key").asText(null);
        if (smtpKey != null && !smtpKey.isBlank()) {
          domain.setSmtpUsername(postalSmtpName);
          domain.setSmtpPassword(smtpKey);
          log.info("SMTP credentials saved domainId={}", domain.getId());
        }
      }
    } catch (ResponseStatusException ex) {
      domain.setDnsStatus("error");
      domain.setDnsError(ex.getReason());
      log.warn("DNS provision failed domainId={} reason={}", domain.getId(), ex.getReason());
    }
  }

  private boolean applyRecordIfChanged(
      com.fasterxml.jackson.databind.JsonNode record,
      String currentValue,
      String currentHost,
      String currentType,
      Integer currentPriority,
      Boolean currentOptional,
      java.util.function.Consumer<String> valueSetter,
      java.util.function.Consumer<String> hostSetter,
      java.util.function.Consumer<String> typeSetter,
      java.util.function.Consumer<Integer> prioritySetter,
      java.util.function.Consumer<Boolean> optionalSetter
  ) {
    if (record == null || record.isMissingNode()) {
      return false;
    }
    String nextValue = record.path("value").asText(null);
    String nextHost = record.path("host").asText(null);
    String nextType = record.path("type").asText(null);
    Integer nextPriority = null;
    Boolean nextOptional = null;
    if (record.has("priority") && !record.get("priority").isNull()) {
      nextPriority = record.path("priority").asInt();
    }
    if (record.has("optional") && !record.get("optional").isNull()) {
      nextOptional = record.path("optional").asBoolean();
    }
    boolean changed = !Objects.equals(currentValue, nextValue)
        || !Objects.equals(currentHost, nextHost)
        || !Objects.equals(currentType, nextType)
        || !Objects.equals(currentPriority, nextPriority)
        || !Objects.equals(currentOptional, nextOptional);
    if (!changed) {
      return false;
    }
    if (valueSetter != null) {
      valueSetter.accept(nextValue);
    }
    if (hostSetter != null) {
      hostSetter.accept(nextHost);
    }
    if (typeSetter != null) {
      typeSetter.accept(nextType);
    }
    if (prioritySetter != null) {
      prioritySetter.accept(nextPriority);
    }
    if (optionalSetter != null) {
      optionalSetter.accept(nextOptional);
    }
    return true;
  }

  private String buildServerName(String domainName) {
    if (domainName != null && !domainName.isBlank()) {
      return domainName;
    }
    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Domain name is required");
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

  private String appendError(String base, String extra) {
    if (extra == null || extra.isBlank()) {
      return base;
    }
    if (base == null || base.isBlank()) {
      return extra;
    }
    return base + "; " + extra;
  }

  private boolean requiredRecordOk(JsonNode records, String id) {
    JsonNode record = findRecord(records, id);
    if (record == null || record.isMissingNode()) {
      return false;
    }
    return record.path("ok").asBoolean(false);
  }

  private String psrpHost(String domainName) {
    return PSRP_HOST_PREFIX + domainName;
  }

  private String returnPathSpfValue() {
    if (postalReturnPathSpf == null || postalReturnPathSpf.isBlank()) {
      return DEFAULT_RETURN_PATH_SPF;
    }
    return postalReturnPathSpf.trim();
  }

  private String returnPathMissingError(String domainName) {
    return "Return Path TXT " + psrpHost(domainName) + " = " + returnPathSpfValue() + " not found";
  }
}
