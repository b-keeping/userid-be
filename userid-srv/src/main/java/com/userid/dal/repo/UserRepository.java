package com.userid.dal.repo;

import com.userid.dal.entity.UserEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long>, UserRepositoryCustom {
  Optional<UserEntity> findByIdAndDomainId(Long id, Long domainId);

  Optional<UserEntity> findByDomainIdAndEmail(Long domainId, String email);

  Optional<UserEntity> findByDomainIdAndEmailPending(Long domainId, String emailPending);

  boolean existsByDomainIdAndEmail(Long domainId, String email);
}
