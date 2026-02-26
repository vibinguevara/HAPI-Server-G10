package ca.uhn.fhir.jpa.starter.smart;

import ca.uhn.fhir.jpa.model.entity.SmartAppToken;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import java.util.Optional;

@Repository
@Transactional
public class SmartAppTokenRepository {

    @PersistenceContext
    private EntityManager entityManager;

    public Optional<SmartAppToken> findById(String jwtId) {
        SmartAppToken token = entityManager.find(SmartAppToken.class, jwtId);
        return Optional.ofNullable(token);
    }

    public List<SmartAppToken> findByClientIdAndPatientId(String clientId, String patientId) {
        return entityManager.createQuery(
                "SELECT t FROM SmartAppToken t WHERE t.clientId = :clientId AND t.patientId = :patientId",
                SmartAppToken.class)
                .setParameter("clientId", clientId)
                .setParameter("patientId", patientId)
                .getResultList();
    }

    public void save(SmartAppToken token) {
        if (entityManager.find(SmartAppToken.class, token.getJwtId()) == null) {
            entityManager.persist(token);
        } else {
            entityManager.merge(token);
        }
    }

    public void saveAll(Iterable<SmartAppToken> tokens) {
        for (SmartAppToken token : tokens) {
            save(token);
        }
    }
}
