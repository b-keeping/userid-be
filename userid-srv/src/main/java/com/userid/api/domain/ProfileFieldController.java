package com.userid.api.domain;

import com.userid.api.common.ApiMessage;
import com.userid.security.AuthPrincipal;
import com.userid.service.ProfileFieldService;
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
@RequestMapping("/api/domains/{domainId}/profile-fields")
@RequiredArgsConstructor
public class ProfileFieldController {
  private final ProfileFieldService profileFieldService;

  @PostMapping
  public ProfileFieldResponse create(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId,
      @Valid @RequestBody ProfileFieldRequest request
  ) {
    return profileFieldService.create(principal.id(), domainId, request);
  }

  @GetMapping
  public List<ProfileFieldResponse> list(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId
  ) {
    return profileFieldService.list(principal.id(), domainId);
  }

  @PutMapping("/{fieldId}")
  public ProfileFieldResponse update(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId,
      @PathVariable Long fieldId,
      @RequestBody ProfileFieldUpdateRequest request
  ) {
    return profileFieldService.update(principal.id(), domainId, fieldId, request);
  }

  @DeleteMapping("/{fieldId}")
  public ApiMessage delete(
      @AuthenticationPrincipal AuthPrincipal principal,
      @PathVariable Long domainId,
      @PathVariable Long fieldId
  ) {
    profileFieldService.delete(principal.id(), domainId, fieldId);
    return new ApiMessage("ok");
  }
}
