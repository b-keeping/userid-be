package com.userid.api.client;

import com.userid.api.user.UserProfileValueResponseDTO;
import java.util.List;

public record AuthServerLoginUserDTO(
    Long id,
    String email,
    boolean confirmed,
    boolean active,
    Long domainId,
    List<UserProfileValueResponseDTO> values
) {}
