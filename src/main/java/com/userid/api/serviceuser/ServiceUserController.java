package com.userid.api.serviceuser;

import com.userid.security.AuthPrincipal;
import com.userid.service.ServiceUserService;
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
@RequestMapping("/api/service-users")
@RequiredArgsConstructor
public class ServiceUserController {
  private final ServiceUserService serviceUserService;

  @PostMapping
  public ServiceUserResponse create(
      @AuthenticationPrincipal AuthPrincipal principal,
      @Valid @RequestBody ServiceUserRequest request
  ) {
    return serviceUserService.create(principal.id(), request);
  }

  @GetMapping
  public List<ServiceUserResponse> list(
      @AuthenticationPrincipal AuthPrincipal principal
  ) {
    return serviceUserService.list(principal.id());
  }

  @GetMapping("/{userId}")
  public ServiceUserResponse get(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long userId
  ) {
    return serviceUserService.get(principal.id(), userId);
  }

  @PostMapping("/{userId}/domains")
  public ServiceUserResponse addDomain(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long userId,
      @Valid @RequestBody ServiceUserDomainRequest request
  ) {
    return serviceUserService.addDomain(principal.id(), userId, request);
  }

  @PutMapping("/{userId}")
  public ServiceUserResponse update(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long userId,
      @RequestBody ServiceUserUpdateRequest request
  ) {
    return serviceUserService.update(principal.id(), userId, request);
  }

  @DeleteMapping("/{userId}/domains/{domainId}")
  public void removeDomain(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long userId,
      @PathVariable Long domainId
  ) {
    serviceUserService.removeDomain(principal.id(), userId, domainId);
  }

  @DeleteMapping("/{userId}")
  public void delete(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long userId
  ) {
    serviceUserService.delete(principal.id(), userId);
  }
}
