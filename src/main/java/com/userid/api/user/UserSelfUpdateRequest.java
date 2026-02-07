package com.userid.api.user;

import java.util.List;

public record UserSelfUpdateRequest(
    String password,
    List<UserProfileValueRequest> values
) {}
