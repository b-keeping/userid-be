package com.userid.api.user;

import java.util.List;

public record UserUpdateRequest(
    String login,
    String email,
    List<UserProfileValueRequest> values
) {}
