package ca.uhn.fhir.jpa.starter.smart;

import ca.uhn.fhir.jpa.model.entity.SmartAppRegistration;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.Optional;

@Repository
@Transactional
public class SmartAppRegistrationRepository {

    @PersistenceContext
    private EntityManager entityManager;

    public Optional<SmartAppRegistration> findById(String clientId) {
        SmartAppRegistration registration = entityManager.find(SmartAppRegistration.class, clientId);
        return Optional.ofNullable(registration);
    }

    public void save(SmartAppRegistration registration) {
        if (entityManager.find(SmartAppRegistration.class, registration.getClientId()) == null) {
            entityManager.persist(registration);
        } else {
            entityManager.merge(registration);
        }
    }
}
