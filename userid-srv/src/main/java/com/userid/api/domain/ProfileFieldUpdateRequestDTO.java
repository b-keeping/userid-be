package com.userid.api.domain;

import com.userid.dal.entity.FieldTypeEnum;

public record ProfileFieldUpdateRequestDTO(
    String name,
    FieldTypeEnum type,
    Boolean mandatory,
    Integer sortOrder
) {}
