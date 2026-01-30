package com.userid.dal.repo;

import com.userid.dal.entity.Domain;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DomainRepository extends JpaRepository<Domain, Long> {
  Optional<Domain> findByCode(String code);
}
