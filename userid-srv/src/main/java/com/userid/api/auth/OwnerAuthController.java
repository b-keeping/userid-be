package com.userid.api.auth;

import com.userid.api.common.ApiMessage;
import com.userid.api.client.AuthServerSocialProvider;
import com.userid.api.owner.OwnerResponse;
import com.userid.service.OwnerAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class OwnerAuthController {
  private final OwnerAuthService ownerAuthService;

  @PostMapping("/login")
  public OwnerLoginResponse login(@Valid @RequestBody OwnerLoginRequest request) {
    return ownerAuthService.login(request);
  }

  @PostMapping("/login/social")
  public OwnerLoginResponse socialLogin(@Valid @RequestBody OwnerSocialAuthRequest request) {
    return ownerAuthService.socialLogin(request);
  }

  @PostMapping("/register")
  public OwnerResponse register(@Valid @RequestBody OwnerRegisterRequest request) {
    return ownerAuthService.register(request);
  }

  @PostMapping("/register/social")
  public OwnerLoginResponse socialRegister(@Valid @RequestBody OwnerSocialAuthRequest request) {
    return ownerAuthService.socialRegister(request);
  }

  @GetMapping("/social/{provider}/config")
  public OwnerSocialProviderConfigResponse socialProviderConfig(@PathVariable String provider) {
    return ownerAuthService.getSocialProviderConfig(parseProvider(provider));
  }

  @GetMapping("/confirm")
  public ApiMessage confirm(@RequestParam String token) {
    ownerAuthService.confirm(token);
    return new ApiMessage("ok");
  }

  @PostMapping("/forgot-password")
  public ApiMessage forgotPassword(@Valid @RequestBody OwnerPasswordResetRequest request) {
    ownerAuthService.requestPasswordReset(request);
    return new ApiMessage("ok");
  }

  @PostMapping("/reset-password")
  public ApiMessage resetPassword(@Valid @RequestBody OwnerPasswordResetConfirmRequest request) {
    ownerAuthService.resetPassword(request);
    return new ApiMessage("ok");
  }

  private AuthServerSocialProvider parseProvider(String provider) {
    try {
      return AuthServerSocialProvider.fromPath(provider);
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage());
    }
  }
}
