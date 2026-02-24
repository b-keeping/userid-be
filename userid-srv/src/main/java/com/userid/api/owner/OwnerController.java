package com.userid.api.owner;

import com.userid.api.common.ApiMessageDTO;
import com.userid.security.AuthPrincipalDTO;
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
  public OwnerResponseDTO create(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @Valid @RequestBody OwnerRequestDTO request
  ) {
    return ownerService.create(principal.id(), request);
  }

  @GetMapping
  public List<OwnerResponseDTO> list(
      @AuthenticationPrincipal AuthPrincipalDTO principal
  ) {
    return ownerService.list(principal.id());
  }

  @GetMapping("/{ownerId}")
  public OwnerResponseDTO get(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long ownerId
  ) {
    return ownerService.get(principal.id(), ownerId);
  }

  @PostMapping("/{ownerId}/domains")
  public OwnerResponseDTO addDomain(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long ownerId,
      @Valid @RequestBody OwnerDomainRequestDTO request
  ) {
    return ownerService.addDomain(principal.id(), ownerId, request);
  }

  @PutMapping("/{ownerId}")
  public OwnerResponseDTO update(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long ownerId,
      @RequestBody OwnerUpdateRequestDTO request
  ) {
    return ownerService.update(principal.id(), ownerId, request);
  }

  @DeleteMapping("/{ownerId}/domains/{domainId}")
  public ApiMessageDTO removeDomain(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long ownerId,
      @PathVariable Long domainId
  ) {
    ownerService.removeDomain(principal.id(), ownerId, domainId);
    return new ApiMessageDTO("ok");
  }

  @DeleteMapping("/{ownerId}")
  public ApiMessageDTO delete(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long ownerId
  ) {
    ownerService.delete(principal.id(), ownerId);
    return new ApiMessageDTO("ok");
  }
}
