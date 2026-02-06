package com.userid.api.domain;

public record DomainResponse(
    Long id,
    String name,
    String dnsStatus,
    String dnsError,
    String verify,
    Boolean verifyStt,
    String spf,
    Boolean spfStt,
    String dkim,
    Boolean dkimStt,
    String mx,
    Boolean mxStt,
    String returnPath,
    Boolean returnPathStt
) {}
