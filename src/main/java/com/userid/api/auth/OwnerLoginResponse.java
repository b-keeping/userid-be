package com.userid.api.auth;

import com.userid.api.owner.OwnerResponse;

public record ServiceLoginResponse(
    String token,
    OwnerResponse user
) {}
