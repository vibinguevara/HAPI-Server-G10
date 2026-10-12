package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Configuration component providing the dynamic FHIR base URL and standard SMART endpoints.
 * Resolved from the FHIR_BASE_URL environment variable / .env file or fhir.base-url property.
 */
@Component
public class FhirServerConfig {

    private static final String DEFAULT_FHIR_BASE_URL = "https://mofapi.medicalofficeforce.co/fhir";

    @Value("${fhir.base-url:${FHIR_BASE_URL:https://mofapi.medicalofficeforce.co/fhir}}")
    private String fhirBaseUrl;

    /**
     * Returns the normalized FHIR base URL without a trailing slash.
     */
    public String getFhirBaseUrl() {
        if (fhirBaseUrl == null || fhirBaseUrl.trim().isEmpty()) {
            return DEFAULT_FHIR_BASE_URL;
        }
        String url = fhirBaseUrl.trim();
        while (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        return url;
    }

    public String getTokenEndpoint() {
        return getFhirBaseUrl() + "/auth/token";
    }

    public String getAuthorizeEndpoint() {
        return getFhirBaseUrl() + "/auth/authorize";
    }

    public String getIntrospectEndpoint() {
        return getFhirBaseUrl() + "/auth/introspect";
    }

    public String getJwksEndpoint() {
        return getFhirBaseUrl() + "/auth/jwks";
    }

    /**
     * Validates whether an incoming audience string matches the configured FHIR base URL,
     * accounting for optional trailing slashes.
     */
    public boolean isAudienceMatch(String aud) {
        if (aud == null) {
            return false;
        }
        String cleanAud = aud.trim();
        while (cleanAud.endsWith("/")) {
            cleanAud = cleanAud.substring(0, cleanAud.length() - 1);
        }
        return getFhirBaseUrl().equalsIgnoreCase(cleanAud);
    }
}
