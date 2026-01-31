package com.userid.api.auth;

import com.userid.service.OwnerAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
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
}
