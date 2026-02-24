package com.userid.api.auth;

import com.userid.api.common.ApiMessageDTO;
import com.userid.api.client.AuthServerSocialProviderEnum;
import com.userid.api.owner.OwnerResponseDTO;
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
  public OwnerLoginResponseDTO login(@Valid @RequestBody OwnerLoginRequestDTO request) {
    return ownerAuthService.login(request);
  }

  @PostMapping("/login/social")
  public OwnerLoginResponseDTO socialLogin(@Valid @RequestBody OwnerSocialAuthRequestDTO request) {
    return ownerAuthService.socialLogin(request);
  }

  @PostMapping("/register")
  public OwnerResponseDTO register(@Valid @RequestBody OwnerRegisterRequestDTO request) {
    return ownerAuthService.register(request);
  }

  @PostMapping("/register/social")
  public OwnerLoginResponseDTO socialRegister(@Valid @RequestBody OwnerSocialAuthRequestDTO request) {
    return ownerAuthService.socialRegister(request);
  }

  @GetMapping("/social/{provider}/config")
  public OwnerSocialProviderConfigResponseDTO socialProviderConfig(@PathVariable String provider) {
    return ownerAuthService.getSocialProviderConfig(parseProvider(provider));
  }

  @GetMapping("/confirm")
  public ApiMessageDTO confirm(@RequestParam String token) {
    ownerAuthService.confirm(token);
    return new ApiMessageDTO("ok");
  }

  @PostMapping("/forgot-password")
  public ApiMessageDTO forgotPassword(@Valid @RequestBody OwnerPasswordResetRequestDTO request) {
    ownerAuthService.requestPasswordReset(request);
    return new ApiMessageDTO("ok");
  }

  @PostMapping("/reset-password")
  public ApiMessageDTO resetPassword(@Valid @RequestBody OwnerPasswordResetConfirmRequestDTO request) {
    ownerAuthService.resetPassword(request);
    return new ApiMessageDTO("ok");
  }

  private AuthServerSocialProviderEnum parseProvider(String provider) {
    try {
      return AuthServerSocialProviderEnum.fromPath(provider);
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage());
    }
  }
}
