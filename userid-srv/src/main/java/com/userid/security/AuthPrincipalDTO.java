package com.userid.security;

import com.userid.dal.entity.OwnerRoleEnum;

public record AuthPrincipalDTO(Long id, String email, OwnerRoleEnum role) {
}
