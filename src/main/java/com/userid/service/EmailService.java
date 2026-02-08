package com.userid.service;

import com.userid.dal.entity.Domain;
import java.util.Properties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class EmailService {
  private static final Logger log = LoggerFactory.getLogger(EmailService.class);
  private final JavaMailSender mailSender;
  private final String fromAddress;
  private final String smtpHost;
  private final int smtpPort;
  private final String smtpProtocol;
  private final String smtpDefaultEncoding;
  private final String smtpUsername;
  private final String smtpPassword;
  private final boolean smtpAuth;
  private final boolean smtpStartTls;
  private final String domainFromLocalPart;

  public EmailService(
      JavaMailSender mailSender,
      @Value("${spring.mail.host:}") String smtpHost,
      @Value("${spring.mail.port:587}") int smtpPort,
      @Value("${spring.mail.protocol:}") String smtpProtocol,
      @Value("${spring.mail.default-encoding:}") String smtpDefaultEncoding,
      @Value("${spring.mail.username:}") String smtpUsername,
      @Value("${spring.mail.password:}") String smtpPassword,
      @Value("${spring.mail.properties.mail.smtp.auth:true}") boolean smtpAuth,
      @Value("${spring.mail.properties.mail.smtp.starttls.enable:true}") boolean smtpStartTls,
      @Value("${auth.email.domain-from-localpart:no-reply}") String domainFromLocalPart,
      @Value("${auth.email.from:no-reply@userid.local}") String fromAddress
  ) {
    this.mailSender = mailSender;
    this.fromAddress = fromAddress;
    this.smtpHost = smtpHost;
    this.smtpPort = smtpPort;
    this.smtpProtocol = smtpProtocol;
    this.smtpDefaultEncoding = smtpDefaultEncoding;
    this.smtpUsername = smtpUsername;
    this.smtpPassword = smtpPassword;
    this.smtpAuth = smtpAuth;
    this.smtpStartTls = smtpStartTls;
    this.domainFromLocalPart = domainFromLocalPart;
  }

  public void sendVerificationEmail(String to, String link) {
    SimpleMailMessage message = new SimpleMailMessage();
    message.setTo(to);
    message.setFrom(fromAddress);
    message.setSubject("Подтверждение регистрации");
    message.setText("Для подтверждения регистрации перейдите по ссылке:\n" + link);
    mailSender.send(message);
  }

  public void sendPasswordResetEmail(String to, String link) {
    SimpleMailMessage message = new SimpleMailMessage();
    message.setTo(to);
    message.setFrom(fromAddress);
    message.setSubject("Сброс пароля");
    message.setText("Для сброса пароля перейдите по ссылке:\n" + link);
    mailSender.send(message);
  }

  public void sendOtpEmail(String to, String code) {
    SimpleMailMessage message = new SimpleMailMessage();
    message.setTo(to);
    message.setFrom(fromAddress);
    message.setSubject("Код подтверждения");
    message.setText("Ваш код подтверждения: " + code);
    mailSender.send(message);
  }

  public void sendUserPasswordResetCode(String to, String code) {
    SimpleMailMessage message = new SimpleMailMessage();
    message.setTo(to);
    message.setFrom(fromAddress);
    message.setSubject("Код для сброса пароля");
    message.setText("Ваш код для сброса пароля: " + code);
    mailSender.send(message);
  }

  public void sendOtpEmail(Domain domain, String to, String code) {
    sendWithDomain(domain, to, "Код подтверждения", "Ваш код подтверждения: " + code);
  }

  public void sendUserPasswordResetCode(Domain domain, String to, String code) {
    sendWithDomain(domain, to, "Код для сброса пароля", "Ваш код для сброса пароля: " + code);
  }

  private void sendWithDomain(Domain domain, String to, String subject, String text) {
    SimpleMailMessage message = new SimpleMailMessage();
    message.setTo(to);
    String from = buildFromAddress(domain);
    message.setFrom(from);
    message.setSubject(subject);
    message.setText(text);
    JavaMailSender sender = resolveSender(domain);
    String smtpUser = domain != null ? domain.getSmtpUsername() : null;
    String smtpPass = domain != null ? domain.getSmtpPassword() : null;
    String smtpUserUsed = smtpUser == null || smtpUser.isBlank() ? smtpUsername : smtpUser;
    log.info(
        "Email send attempt domainId={} domainName={} to={} from={} smtpHost={} smtpPort={} smtpUser={} smtpUserUsed={} smtpPassPresent={} smtpAuth={} startTls={}",
        domain != null ? domain.getId() : null,
        domain != null ? domain.getName() : null,
        to,
        from,
        smtpHost,
        smtpPort,
        smtpUser,
        smtpUserUsed,
        smtpPass != null && !smtpPass.isBlank(),
        smtpAuth,
        smtpStartTls
    );
    try {
      sender.send(message);
      log.info(
          "Email send success domainId={} domainName={} to={} from={}",
          domain != null ? domain.getId() : null,
          domain != null ? domain.getName() : null,
          to,
          from
      );
    } catch (Exception ex) {
      Long domainId = domain != null ? domain.getId() : null;
      String domainName = domain != null ? domain.getName() : null;
      log.error(
          "Email send failed domainId={} domainName={} to={} smtpHost={} smtpUser={} smtpUserUsed={} error={}",
          domainId, domainName, to, smtpHost, smtpUser, smtpUserUsed, ex.getMessage(), ex
      );
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Email send failed");
    }
  }

  private String buildFromAddress(Domain domain) {
    if (domain == null || domain.getName() == null || domain.getName().isBlank()) {
      return fromAddress;
    }
    return domainFromLocalPart + "@" + domain.getName();
  }

  private JavaMailSender resolveSender(Domain domain) {
    if (domain == null) {
      return mailSender;
    }
    if (smtpHost == null || smtpHost.isBlank()) {
      return mailSender;
    }
    String username = domain.getSmtpUsername();
    String password = domain.getSmtpPassword();
    if (username == null || username.isBlank()) {
      username = smtpUsername;
    }
    if (password == null || password.isBlank()) {
      return mailSender;
    }
    if (username == null || username.isBlank()) {
      return mailSender;
    }

    JavaMailSenderImpl sender = new JavaMailSenderImpl();
    sender.setHost(smtpHost);
    sender.setPort(smtpPort);
    sender.setUsername(username);
    sender.setPassword(password);
    if (smtpProtocol != null && !smtpProtocol.isBlank()) {
      sender.setProtocol(smtpProtocol);
    }
    if (smtpDefaultEncoding != null && !smtpDefaultEncoding.isBlank()) {
      sender.setDefaultEncoding(smtpDefaultEncoding);
    }
    Properties props = new Properties();
    props.put("mail.smtp.auth", String.valueOf(smtpAuth));
    props.put("mail.smtp.starttls.enable", String.valueOf(smtpStartTls));
    sender.setJavaMailProperties(props);
    return sender;
  }
}
