package com.userid.api.auth;

import com.userid.api.owner.OwnerResponse;

public record OwnerLoginResponse(
    String token,
    OwnerResponse user
) {}
