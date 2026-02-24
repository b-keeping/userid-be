package com.userid.api.auth;

import com.userid.api.owner.OwnerResponseDTO;

public record OwnerLoginResponseDTO(
    String token,
    OwnerResponseDTO user
) {}
