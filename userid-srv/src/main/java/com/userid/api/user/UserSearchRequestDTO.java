package com.userid.api.user;

import java.util.List;

public record UserSearchRequestDTO(
    List<UserProfileFilterRequestDTO> filters
) {}
