package com.userid.api.domain;

import com.userid.dal.entity.FieldType;

public record ProfileFieldUpdateRequest(
    String name,
    FieldType type,
    Boolean mandatory,
    Integer sortOrder
) {}
