package com.userid.dal.repo;

import com.userid.dal.entity.OtpType;
import com.userid.dal.entity.OtpUser;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OtpUserRepository extends JpaRepository<OtpUser, Long> {
  Optional<OtpUser> findByCodeAndType(String code, OtpType type);

  boolean existsByCodeAndType(String code, OtpType type);

  void deleteByUserIdAndType(Long userId, OtpType type);
}
