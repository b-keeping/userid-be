package com.userid.api.domain;

import com.userid.dal.entity.FieldType;

public record ProfileFieldResponse(
    Long id,
    String name,
    FieldType type,
    boolean mandatory,
    Integer sortOrder
) {}
