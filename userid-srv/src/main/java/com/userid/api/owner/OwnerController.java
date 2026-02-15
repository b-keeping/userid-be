package com.userid.api.owner;

import com.userid.api.common.ApiMessage;
import com.userid.security.AuthPrincipal;
import com.userid.service.OwnerService;
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
@RequestMapping("/api/owners")
@RequiredArgsConstructor
public class OwnerController {
  private final OwnerService ownerService;

  @PostMapping
  public OwnerResponse create(
      @AuthenticationPrincipal AuthPrincipal principal,
      @Valid @RequestBody OwnerRequest request
  ) {
    return ownerService.create(principal.id(), request);
  }

  @GetMapping
  public List<OwnerResponse> list(
      @AuthenticationPrincipal AuthPrincipal principal
  ) {
    return ownerService.list(principal.id());
  }

  @GetMapping("/{ownerId}")
  public OwnerResponse get(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long ownerId
  ) {
    return ownerService.get(principal.id(), ownerId);
  }

  @PostMapping("/{ownerId}/domains")
  public OwnerResponse addDomain(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long ownerId,
      @Valid @RequestBody OwnerDomainRequest request
  ) {
    return ownerService.addDomain(principal.id(), ownerId, request);
  }

  @PutMapping("/{ownerId}")
  public OwnerResponse update(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long ownerId,
      @RequestBody OwnerUpdateRequest request
  ) {
    return ownerService.update(principal.id(), ownerId, request);
  }

  @DeleteMapping("/{ownerId}/domains/{domainId}")
  public ApiMessage removeDomain(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long ownerId,
      @PathVariable Long domainId
  ) {
    ownerService.removeDomain(principal.id(), ownerId, domainId);
    return new ApiMessage("ok");
  }

  @DeleteMapping("/{ownerId}")
  public ApiMessage delete(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long ownerId
  ) {
    ownerService.delete(principal.id(), ownerId);
    return new ApiMessage("ok");
  }
}
