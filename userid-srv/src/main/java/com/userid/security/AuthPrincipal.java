package com.userid.security;

import com.userid.dal.entity.OwnerRole;

public record AuthPrincipal(Long id, String email, OwnerRole role) {
}
