package com.userid.api.auth;

import com.userid.api.common.ApiMessage;
import com.userid.api.owner.OwnerResponse;
import com.userid.service.OwnerAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class OwnerAuthController {
  private final OwnerAuthService ownerAuthService;

  @PostMapping("/login")
  public OwnerLoginResponse login(@Valid @RequestBody OwnerLoginRequest request) {
    return ownerAuthService.login(request);
  }

  @PostMapping("/register")
  public OwnerResponse register(@Valid @RequestBody OwnerRegisterRequest request) {
    return ownerAuthService.register(request);
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
}
