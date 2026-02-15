package com.userid.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import javax.naming.NamingException;
import org.junit.jupiter.api.Test;

class DnsLookupServiceTests {

  @Test
  void hasTxtRecordReturnsTrueForMatchingValue() {
    DnsLookupService service = new TestDnsLookupService(
        List.of("\"v=spf1 a:post.userid.sh -all\""),
        false);

    boolean result = service.hasTxtRecord("psrp.example.com", "v=spf1 a:post.userid.sh -all");

    assertThat(result).isTrue();
  }

  @Test
  void hasTxtRecordReturnsFalseWhenValueDiffers() {
    DnsLookupService service = new TestDnsLookupService(
        List.of("\"v=spf1 include:_spf.google.com ~all\""),
        false);

    boolean result = service.hasTxtRecord("psrp.example.com", "v=spf1 a:post.userid.sh -all");

    assertThat(result).isFalse();
  }

  @Test
  void hasTxtRecordReturnsFalseOnLookupError() {
    DnsLookupService service = new TestDnsLookupService(List.of(), true);

    boolean result = service.hasTxtRecord("psrp.example.com", "v=spf1 a:post.userid.sh -all");

    assertThat(result).isFalse();
  }

  private static final class TestDnsLookupService extends DnsLookupService {
    private final List<String> values;
    private final boolean fail;

    private TestDnsLookupService(List<String> values, boolean fail) {
      this.values = values;
      this.fail = fail;
    }

    @Override
    protected List<String> resolveTxtRecords(String host) throws NamingException {
      if (fail) {
        throw new NamingException("test failure");
      }
      return values;
    }
  }
}
