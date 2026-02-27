package com.userid.api.client;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

@AutoConfiguration
@EnableConfigurationProperties(AuthServerApiProperties.class)
public class UseridApiAutoConfiguration {
  @Bean
  @ConditionalOnMissingBean
  public AuthServerApiClient authServerApiClient(
      RestTemplate restTemplate,
      AuthServerApiProperties properties,
      UseridApiMessageResolver messageResolver
  ) {
    return new AuthServerApiClient(restTemplate, properties, messageResolver);
  }

  @Bean
  @ConditionalOnMissingBean
  public UseridApiMessageResolver useridApiMessageResolver(AuthServerApiProperties properties) {
    return new UseridApiMessageResolver(properties);
  }

  @Bean
  @ConditionalOnMissingBean
  public RestTemplate authServerRestTemplate() {
    return new RestTemplate();
  }
}
