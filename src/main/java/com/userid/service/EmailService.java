package com.userid.service;

import com.userid.dal.entity.Domain;
import java.util.Properties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.mail.MailProperties;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
  private final JavaMailSender mailSender;
  private final MailProperties mailProperties;
  private final String fromAddress;

  public EmailService(
      JavaMailSender mailSender,
      MailProperties mailProperties,
      @Value("${auth.email.from:no-reply@userid.local}") String fromAddress
  ) {
    this.mailSender = mailSender;
    this.mailProperties = mailProperties;
    this.fromAddress = fromAddress;
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
    message.setFrom(fromAddress);
    message.setSubject(subject);
    message.setText(text);
    resolveSender(domain).send(message);
  }

  private JavaMailSender resolveSender(Domain domain) {
    if (domain == null) {
      return mailSender;
    }
    String username = domain.getSmtpUsername();
    if (username == null || username.isBlank()) {
      return mailSender;
    }
    String host = mailProperties.getHost();
    if (host == null || host.isBlank()) {
      return mailSender;
    }
    String password = domain.getSmtpPassword();
    if (password == null || password.isBlank()) {
      password = username;
    }

    JavaMailSenderImpl sender = new JavaMailSenderImpl();
    sender.setHost(host);
    sender.setPort(mailProperties.getPort());
    sender.setUsername(username);
    sender.setPassword(password);
    if (mailProperties.getProtocol() != null && !mailProperties.getProtocol().isBlank()) {
      sender.setProtocol(mailProperties.getProtocol());
    }
    if (mailProperties.getDefaultEncoding() != null && !mailProperties.getDefaultEncoding().isBlank()) {
      sender.setDefaultEncoding(mailProperties.getDefaultEncoding());
    }
    Properties props = new Properties();
    props.putAll(mailProperties.getProperties());
    sender.setJavaMailProperties(props);
    return sender;
  }
}
