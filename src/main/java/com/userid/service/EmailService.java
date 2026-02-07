package com.userid.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
  private final JavaMailSender mailSender;
  private final String fromAddress;

  public EmailService(
      JavaMailSender mailSender,
      @Value("${auth.email.from:no-reply@userid.local}") String fromAddress
  ) {
    this.mailSender = mailSender;
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
}
