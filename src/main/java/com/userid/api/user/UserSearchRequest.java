package com.userid.api.user;

import java.util.List;

public record UserSearchRequest(
    List<UserProfileFilterRequest> filters
) {}
