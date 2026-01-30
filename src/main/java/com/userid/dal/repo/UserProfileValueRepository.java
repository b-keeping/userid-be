package com.userid.dal.repo;

import com.userid.dal.entity.UserProfileValue;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserProfileValueRepository extends JpaRepository<UserProfileValue, Long> {
  List<UserProfileValue> findByUserId(Long userId);

  void deleteByUserId(Long userId);

  void deleteByFieldId(Long fieldId);

  long countByFieldId(Long fieldId);
}
