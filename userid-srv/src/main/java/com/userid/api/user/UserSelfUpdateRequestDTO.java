package com.userid.api.user;

import java.util.List;

public record UserSelfUpdateRequestDTO(
    String password,
    List<UserProfileValueRequestDTO> values
) {}
