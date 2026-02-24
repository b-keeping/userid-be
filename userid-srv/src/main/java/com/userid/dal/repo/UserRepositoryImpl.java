package com.userid.dal.repo;

import com.userid.dal.entity.ProfileFieldEntity;
import com.userid.dal.entity.UserEntity;
import com.userid.dal.entity.UserProfileValueEntity;
import com.userid.service.UserSearchFilterDTO;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Fetch;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepositoryImpl implements UserRepositoryCustom {
  @PersistenceContext
  private EntityManager entityManager;

  @Override
  public List<UserEntity> searchByDomainAndFilters(Long domainId, List<UserSearchFilterDTO> filters) {
    CriteriaBuilder cb = entityManager.getCriteriaBuilder();
    CriteriaQuery<UserEntity> cq = cb.createQuery(UserEntity.class);
    Root<UserEntity> userRoot = cq.from(UserEntity.class);

    List<Predicate> predicates = new ArrayList<>();
    predicates.add(cb.equal(userRoot.get("domain").get("id"), domainId));

    for (UserSearchFilterDTO filter : filters) {
      Subquery<Long> subquery = cq.subquery(Long.class);
      Root<UserProfileValueEntity> valueRoot = subquery.from(UserProfileValueEntity.class);
      Join<UserProfileValueEntity, ProfileFieldEntity> fieldJoin = valueRoot.join("field", JoinType.INNER);

      List<Predicate> subPredicates = new ArrayList<>();
      subPredicates.add(cb.equal(valueRoot.get("user").get("id"), userRoot.get("id")));
      subPredicates.add(cb.equal(fieldJoin.get("id"), filter.fieldId()));

      switch (filter.type()) {
        case STRING, NUMERIC -> subPredicates.add(cb.equal(valueRoot.get("valueString"), filter.stringValue()));
        case BOOLEAN -> subPredicates.add(cb.equal(valueRoot.get("valueBoolean"), filter.booleanValue()));
        case INTEGER -> subPredicates.add(cb.equal(valueRoot.get("valueInteger"), filter.integerValue()));
        case DECIMAL -> subPredicates.add(cb.equal(valueRoot.get("valueDecimal"), filter.decimalValue()));
        case DATE -> subPredicates.add(cb.equal(valueRoot.get("valueDate"), filter.dateValue()));
        case TIME -> subPredicates.add(cb.equal(valueRoot.get("valueTime"), filter.timeValue()));
        case TIMESTAMP -> subPredicates.add(cb.equal(valueRoot.get("valueTimestamp"), filter.timestampValue()));
      }

      subquery.select(valueRoot.get("id")).where(subPredicates.toArray(Predicate[]::new));
      predicates.add(cb.exists(subquery));
    }

    cq.select(userRoot).distinct(true).where(predicates.toArray(Predicate[]::new));

    TypedQuery<UserEntity> query = entityManager.createQuery(cq);
    return query.getResultList();
  }
}
