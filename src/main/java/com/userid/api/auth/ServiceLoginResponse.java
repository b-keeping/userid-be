package com.userid.api.auth;

import com.userid.api.serviceuser.ServiceUserResponse;

public record ServiceLoginResponse(
    String token,
    ServiceUserResponse user
) {}
