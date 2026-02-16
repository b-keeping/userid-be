package com.userid.api.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
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
    ObjectMapper objectMapper = restTemplate.getMessageConverters().stream()
        .filter(MappingJackson2HttpMessageConverter.class::isInstance)
        .map(MappingJackson2HttpMessageConverter.class::cast)
        .map(MappingJackson2HttpMessageConverter::getObjectMapper)
        .findFirst()
        .orElseGet(() -> new ObjectMapper().findAndRegisterModules());
    return new AuthServerApiClient(restTemplate, properties, objectMapper, messageResolver);
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
