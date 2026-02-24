package com.userid.api.client;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "userid.api")
public class AuthServerApiProperties {
  private boolean enabled = false;
  private String baseUrl;
  private Long domainId;
  private String apiToken;
  private UseridApiLanguageEnum language = UseridApiLanguageEnum.EN;
}
