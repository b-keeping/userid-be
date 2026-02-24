package com.userid.api.client;

import java.util.List;

public record AuthServerUserSelfUpdateRequestDTO(
    String password,
    List<AuthServerProfileValueDTO> values
) {}
