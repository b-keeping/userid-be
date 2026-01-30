package com.userid.dal.repo;

import com.userid.dal.entity.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long>, UserRepositoryCustom {
  @EntityGraph(attributePaths = {"values", "values.field"})
  Optional<User> findByIdAndDomainId(Long id, Long domainId);

  boolean existsByDomainIdAndLogin(Long domainId, String login);
}
