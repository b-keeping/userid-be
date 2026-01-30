package com.userid.api.domain;

import com.userid.dal.entity.FieldType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record ProfileFieldRequest(
    @NotBlank String key,
    @NotBlank String label,
    @NotNull FieldType type,
    @NotNull Boolean mandatory,
    Integer sortOrder
) {}
