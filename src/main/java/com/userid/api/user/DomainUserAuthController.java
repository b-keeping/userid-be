package com.userid.api.user;

import com.userid.api.common.ApiMessage;
import com.userid.service.DomainUserAuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/domains/{domainId}/users")
@RequiredArgsConstructor
public class DomainUserAuthController {
  private final DomainUserAuthService domainUserAuthService;

  @PostMapping("/login")
  public UserLoginResponse login(
      @PathVariable Long domainId,
      @Valid @RequestBody UserLoginRequest request
  ) {
    return domainUserAuthService.login(domainId, request);
  }

  @PostMapping("/confirm")
  public ApiMessage confirm(
      @PathVariable Long domainId,
      @Valid @RequestBody UserConfirmRequest request
  ) {
    return domainUserAuthService.confirm(domainId, request);
  }

  @PostMapping("/forgot-password")
  public ApiMessage forgotPassword(
      @PathVariable Long domainId,
      @Valid @RequestBody UserForgotPasswordRequest request
  ) {
    return domainUserAuthService.forgotPassword(domainId, request);
  }

  @PostMapping("/reset-password")
  public ApiMessage resetPassword(
      @PathVariable Long domainId,
      @Valid @RequestBody UserResetPasswordRequest request
  ) {
    return domainUserAuthService.resetPassword(domainId, request);
  }

  @PostMapping("/resend-verification")
  public ApiMessage resendVerification(
      @PathVariable Long domainId,
      @Valid @RequestBody UserForgotPasswordRequest request
  ) {
    return domainUserAuthService.resendVerification(domainId, request);
  }

  @PutMapping("/me")
  public UserResponse updateSelf(
      @PathVariable Long domainId,
      HttpServletRequest request,
      @RequestBody UserSelfUpdateRequest body
  ) {
    return domainUserAuthService.updateSelf(domainId, request, body);
  }
}
