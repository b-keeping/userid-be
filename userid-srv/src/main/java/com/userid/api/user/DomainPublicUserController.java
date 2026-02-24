package com.userid.api.user;

import com.userid.api.common.ApiMessageDTO;
import com.userid.api.client.AuthServerSocialAuthRequestDTO;
import com.userid.api.client.AuthServerSocialLoginRequestDTO;
import com.userid.api.client.AuthServerSocialProviderEnum;
import com.userid.api.client.DomainSocialProviderConfigResponseDTO;
import com.userid.api.client.UseridApiEndpoints;
import com.userid.security.DomainApiPrincipalDTO;
import com.userid.service.DomainSocialProviderConfigService;
import com.userid.service.DomainUserAuthService;
import com.userid.service.DomainUserSocialAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
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
  private final DomainUserAuthService domainUserAuthService;
  private final DomainUserSocialAuthService domainUserSocialAuthService;
  private final DomainSocialProviderConfigService domainSocialProviderConfigService;

  @PostMapping
  public UserLoginResponseDTO register(
      @AuthenticationPrincipal DomainApiPrincipalDTO principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserRegistrationRequestDTO request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.register(domainId, request);
  }

  @PostMapping(UseridApiEndpoints.LOGIN)
  public UserLoginResponseDTO login(
      @AuthenticationPrincipal DomainApiPrincipalDTO principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserLoginRequestDTO request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.login(domainId, request);
  }

  @PostMapping(UseridApiEndpoints.SOCIAL_LOGIN)
  public UserLoginResponseDTO socialLogin(
      @AuthenticationPrincipal DomainApiPrincipalDTO principal,
      @PathVariable Long domainId,
      @RequestBody AuthServerSocialAuthRequestDTO request
  ) {
    requireDomain(principal, domainId);
    if (request == null) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social auth payload is required");
    }
    return domainUserSocialAuthService.login(
        domainId,
        parseProvider(request.provider()),
        new AuthServerSocialLoginRequestDTO(
            request.code(),
            request.codeVerifier(),
            request.deviceId(),
            request.state()));
  }

  @GetMapping(UseridApiEndpoints.SOCIAL_PROVIDER_CONFIG)
  public DomainSocialProviderConfigResponseDTO socialProviderConfig(
      @AuthenticationPrincipal DomainApiPrincipalDTO principal,
      @PathVariable Long domainId,
      @PathVariable String provider
  ) {
    requireDomain(principal, domainId);
    return domainSocialProviderConfigService.getForDomainApi(
        domainId,
        parseProvider(provider));
  }

  @PostMapping(UseridApiEndpoints.CONFIRM)
  public UserLoginResponseDTO confirm(
      @AuthenticationPrincipal DomainApiPrincipalDTO principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserConfirmRequestDTO request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.confirm(domainId, request);
  }

  @PostMapping(UseridApiEndpoints.FORGOT_PASSWORD)
  public ApiMessageDTO forgotPassword(
      @AuthenticationPrincipal DomainApiPrincipalDTO principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserForgotPasswordRequestDTO request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.forgotPassword(domainId, request);
  }

  @PostMapping(UseridApiEndpoints.RESET_PASSWORD)
  public ApiMessageDTO resetPassword(
      @AuthenticationPrincipal DomainApiPrincipalDTO principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserResetPasswordRequestDTO request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.resetPassword(domainId, request);
  }

  @PostMapping(UseridApiEndpoints.RESEND_VERIFICATION)
  public ApiMessageDTO resendVerification(
      @AuthenticationPrincipal DomainApiPrincipalDTO principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserForgotPasswordRequestDTO request
  ) {
    requireDomain(principal, domainId);
    return domainUserAuthService.resendVerification(domainId, request);
  }

  private void requireDomain(DomainApiPrincipalDTO principal, Long domainId) {
    if (principal == null || !domainId.equals(principal.domainId())) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Domain mismatch");
    }
  }

  private AuthServerSocialProviderEnum parseProvider(String provider) {
    try {
      return AuthServerSocialProviderEnum.fromPath(provider);
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage());
    }
  }
}
