package com.userid.api.user;

import jakarta.validation.constraints.Email;
import java.util.List;

public record UserUpdateRequest(
    String password,
    @Email String email,
    List<UserProfileValueRequest> values
) {}
