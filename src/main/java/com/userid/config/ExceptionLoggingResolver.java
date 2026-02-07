package com.userid.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.server.ResponseStatusException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ExceptionLoggingResolver implements HandlerExceptionResolver {
  private static final Logger log = LoggerFactory.getLogger(ExceptionLoggingResolver.class);

  @Override
  public ModelAndView resolveException(
      HttpServletRequest request,
      HttpServletResponse response,
      Object handler,
      Exception ex
  ) {
    int status = response.getStatus();
    if (ex instanceof ResponseStatusException rse) {
      status = rse.getStatusCode().value();
    }

    String path = request.getRequestURI();
    String method = request.getMethod();
    String message = ex.getMessage();

    if (status >= 500 || status == 0) {
      log.error("Request failed method={} path={} status={} message={}", method, path, status, message, ex);
    } else {
      log.warn("Request failed method={} path={} status={} message={}", method, path, status, message);
    }

    return null;
  }
}
