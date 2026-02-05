package com.userid.api.domain;

import com.fasterxml.jackson.databind.JsonNode;

public record DomainResponse(
    Long id,
    String name,
    String postalStatus,
    String postalError,
    JsonNode postalDomain,
    JsonNode postalDnsRecords,
    JsonNode postalDnsCheck,
    JsonNode postalVerification,
    JsonNode postalSpf,
    JsonNode postalDkim,
    JsonNode postalReturnPath,
    JsonNode postalMx
) {}
