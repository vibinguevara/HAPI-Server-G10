package ca.uhn.fhir.jpa.starter.smart;

import ca.uhn.fhir.jpa.model.entity.SystemConfiguration;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.Optional;

@Repository
@Transactional
public class SystemConfigurationRepository {

    @PersistenceContext
    private EntityManager entityManager;

    public Optional<SystemConfiguration> findById(String configKey) {
        SystemConfiguration config = entityManager.find(SystemConfiguration.class, configKey);
        return Optional.ofNullable(config);
    }

    public void save(SystemConfiguration config) {
        if (entityManager.find(SystemConfiguration.class, config.getConfigKey()) == null) {
            entityManager.persist(config);
        } else {
            entityManager.merge(config);
        }
    }
}
