package com.userid.service;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class DnsLookupService {
  private static final Logger log = LoggerFactory.getLogger(DnsLookupService.class);

  public boolean hasTxtRecord(String host, String expectedValue) {
    String normalizedExpected = normalizeTxt(expectedValue);
    try {
      List<String> values = resolveTxtRecords(host);
      for (String value : values) {
        if (normalizeTxt(value).equalsIgnoreCase(normalizedExpected)) {
          return true;
        }
      }
      return false;
    } catch (NamingException ex) {
      log.warn("DNS TXT lookup failed host={} reason={}", host, ex.getMessage());
      return false;
    }
  }

  protected List<String> resolveTxtRecords(String host) throws NamingException {
    Hashtable<String, String> environment = new Hashtable<>();
    environment.put(DirContext.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
    DirContext context = new InitialDirContext(environment);
    try {
      Attributes attributes = context.getAttributes(host, new String[]{"TXT"});
      Attribute txt = attributes.get("TXT");
      List<String> values = new ArrayList<>();
      if (txt == null) {
        return values;
      }
      for (int i = 0; i < txt.size(); i++) {
        Object item = txt.get(i);
        values.add(item == null ? null : item.toString());
      }
      return values;
    } finally {
      context.close();
    }
  }

  static String normalizeTxt(String value) {
    if (value == null) {
      return "";
    }
    return value.replace("\"", "").replaceAll("\\s+", " ").trim();
  }
}
