package com.userid.api.client;

import java.util.List;

public record AuthServerUserSelfUpdateRequest(
    String password,
    List<AuthServerProfileValue> values
) {}
