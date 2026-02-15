package com.userid.api.user;

import com.userid.api.client.UseridApiEndpoints;
import com.userid.service.DomainUserAuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(UseridApiEndpoints.EXTERNAL_DOMAIN_USERS_BASE)
@RequiredArgsConstructor
public class DomainUserAuthController {
  private final DomainUserAuthService domainUserAuthService;

  @PutMapping(UseridApiEndpoints.ME)
  public UserResponse updateSelf(
      @PathVariable Long domainId,
      HttpServletRequest request,
      @RequestBody UserSelfUpdateRequest body
  ) {
    return domainUserAuthService.updateSelf(domainId, request, body);
  }
}
