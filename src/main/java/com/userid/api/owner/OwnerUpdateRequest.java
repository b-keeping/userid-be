package com.userid.api.owner;

import com.userid.dal.entity.OwnerRole;
import java.util.List;

public record OwnerUpdateRequest(
    String username,
    String password,
    OwnerRole role,
    List<Long> domainIds
) {}
