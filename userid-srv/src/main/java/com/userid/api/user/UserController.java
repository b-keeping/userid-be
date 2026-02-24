package com.userid.api.user;

import com.userid.api.common.ApiMessageDTO;
import com.userid.security.AuthPrincipalDTO;
import com.userid.service.UserService;
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
@RequestMapping("/api/domains/{domainId}/users")
@RequiredArgsConstructor
public class UserController {
  private final UserService userService;

  @PostMapping
  public UserResponseDTO register(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId,
      @Valid @RequestBody UserRegistrationRequestDTO request
  ) {
    return userService.register(principal.id(), domainId, request);
  }

  @GetMapping("/{userId}")
  public UserResponseDTO get(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId,
      @PathVariable Long userId
  ) {
    return userService.get(principal.id(), domainId, userId);
  }

  @PostMapping("/search")
  public List<UserResponseDTO> search(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId,
      @RequestBody UserSearchRequestDTO request
  ) {
    return userService.search(principal.id(), domainId, request);
  }

  @PutMapping("/{userId}")
  public UserResponseDTO update(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId,
      @PathVariable Long userId,
      @RequestBody UserUpdateRequestDTO request
  ) {
    return userService.update(principal.id(), domainId, userId, request);
  }

  @DeleteMapping("/{userId}")
  public ApiMessageDTO delete(
      @AuthenticationPrincipal AuthPrincipalDTO principal,
      @PathVariable Long domainId,
      @PathVariable Long userId
  ) {
    userService.delete(principal.id(), domainId, userId);
    return new ApiMessageDTO("ok");
  }
}
