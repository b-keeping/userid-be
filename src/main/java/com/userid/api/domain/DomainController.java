package com.userid.api.domain;

import com.userid.api.common.ApiMessage;
import com.userid.api.domain.DomainJwtSecretResponse;
import com.userid.security.AuthPrincipal;
import com.userid.service.DomainService;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/domains")
@RequiredArgsConstructor
public class DomainController {
  private final DomainService domainService;

  @PostMapping
  public DomainResponse create(
      @AuthenticationPrincipal AuthPrincipal principal,
      @Valid @RequestBody DomainRequest request
  ) {
    return domainService.create(principal.id(), request);
  }

  @GetMapping
  public List<DomainResponse> list(
      @AuthenticationPrincipal AuthPrincipal principal
  ) {
    return domainService.list(principal.id());
  }

  @PutMapping("/{domainId}")
  public DomainResponse update(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId,
      @RequestBody DomainUpdateRequest request
  ) {
    return domainService.update(principal.id(), domainId, request);
  }

  @PostMapping("/{domainId}/dns-check")
  public DomainResponse dnsCheck(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    return domainService.checkDns(principal.id(), domainId);
  }

  @PostMapping("/{domainId}/verify")
  public DomainResponse verify(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    return domainService.verifyDomain(principal.id(), domainId);
  }

  @GetMapping("/{domainId}/user-jwt-secret")
  public DomainJwtSecretResponse getUserJwtSecret(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    return domainService.getUserJwtSecret(principal.id(), domainId);
  }

  @PostMapping("/{domainId}/user-jwt-secret/rotate")
  public DomainJwtSecretResponse rotateUserJwtSecret(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    return domainService.rotateUserJwtSecret(principal.id(), domainId);
  }

  @DeleteMapping("/{domainId}")
  public ApiMessage delete(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    domainService.delete(principal.id(), domainId);
    return new ApiMessage("ok");
  }
}
