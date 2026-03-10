package ca.uhn.fhir.jpa.model.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Column;

@Entity
@Table(name = "SYSTEM_CONFIGURATION")
public class SystemConfiguration {

    @Id
    @Column(name = "CONFIG_KEY", length = 100)
    private String configKey;

    @Column(name = "CONFIG_VALUE", length = 255)
    private String configValue;

    public SystemConfiguration() {
    }

    public SystemConfiguration(String configKey, String configValue) {
        this.configKey = configKey;
        this.configValue = configValue;
    }

    public String getConfigKey() {
        return configKey;
    }

    public void setConfigKey(String configKey) {
        this.configKey = configKey;
    }

    public String getConfigValue() {
        return configValue;
    }

    public void setConfigValue(String configValue) {
        this.configValue = configValue;
    }
}
