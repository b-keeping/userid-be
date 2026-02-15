package com.userid.api.user;

import com.userid.api.common.ApiMessage;
import com.userid.api.client.UseridApiEndpoints;
import com.userid.security.DomainApiPrincipal;
import com.userid.service.DomainUserAuthService;
import com.userid.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping(UseridApiEndpoints.EXTERNAL_DOMAIN_USERS_BASE)
@RequiredArgsConstructor
public class DomainPublicUserController {
  private final UserService userService;
  private final DomainUserAuthService domainUserAuthService;

  @PostMapping
  public UserResponse register(
      @AuthenticationPrincipal DomainApiPrincipal principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserRegistrationRequest request
  ) {
    requireDomain(principal, domainId);
    return userService.registerByDomain(domainId, request);
  }

  @PostMapping(UseridApiEndpoints.LOGIN)
  public UserLoginResponse login(
      @AuthenticationPrincipal DomainApiPrincipal principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserLoginRequest request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.login(domainId, request);
  }

  @PostMapping(UseridApiEndpoints.CONFIRM)
  public ApiMessage confirm(
      @AuthenticationPrincipal DomainApiPrincipal principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserConfirmRequest request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.confirm(domainId, request);
  }

  @PostMapping(UseridApiEndpoints.FORGOT_PASSWORD)
  public ApiMessage forgotPassword(
      @AuthenticationPrincipal DomainApiPrincipal principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserForgotPasswordRequest request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.forgotPassword(domainId, request);
  }

  @PostMapping(UseridApiEndpoints.RESET_PASSWORD)
  public ApiMessage resetPassword(
      @AuthenticationPrincipal DomainApiPrincipal principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserResetPasswordRequest request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.resetPassword(domainId, request);
  }

  @PostMapping(UseridApiEndpoints.RESEND_VERIFICATION)
  public ApiMessage resendVerification(
      @AuthenticationPrincipal DomainApiPrincipal principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserForgotPasswordRequest request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.resendVerification(domainId, request);
  }

  private void requireDomain(DomainApiPrincipal principal, Long domainId) {
    if (principal == null || !domainId.equals(principal.domainId())) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Domain mismatch");
    }
  }
}
