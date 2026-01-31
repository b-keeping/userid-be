package com.userid.api.user;

import jakarta.validation.constraints.NotBlank;
import java.util.List;

public record UserRegistrationRequest(
    @NotBlank String login,
    @NotBlank String password,
    String email,
    List<UserProfileValueRequest> values
) {}
