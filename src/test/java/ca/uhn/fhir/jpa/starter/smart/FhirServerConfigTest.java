package ca.uhn.fhir.jpa.starter.smart;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

class FhirServerConfigTest {

    @Test
    void testDefaultValues() {
        FhirServerConfig config = new FhirServerConfig();
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir", config.getFhirBaseUrl());
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/token", config.getTokenEndpoint());
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/authorize", config.getAuthorizeEndpoint());
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/introspect", config.getIntrospectEndpoint());
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/jwks", config.getJwksEndpoint());
    }

    @Test
    void testCustomBaseUrlTrailingSlashSanitization() {
        FhirServerConfig config = new FhirServerConfig();
        ReflectionTestUtils.setField(config, "fhirBaseUrl", "https://mofapi.medicalofficeforce.co/fhir///");

        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir", config.getFhirBaseUrl());
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/token", config.getTokenEndpoint());
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/authorize", config.getAuthorizeEndpoint());
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/introspect", config.getIntrospectEndpoint());
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/jwks", config.getJwksEndpoint());
    }

    @Test
    void testAudienceMatch() {
        FhirServerConfig config = new FhirServerConfig();
        ReflectionTestUtils.setField(config, "fhirBaseUrl", "https://mofapi.medicalofficeforce.co/fhir");

        Assertions.assertTrue(config.isAudienceMatch("https://mofapi.medicalofficeforce.co/fhir"));
        Assertions.assertTrue(config.isAudienceMatch("https://mofapi.medicalofficeforce.co/fhir/"));
        Assertions.assertFalse(config.isAudienceMatch("http://localhost:8080/fhir"));
        Assertions.assertFalse(config.isAudienceMatch(null));
    }

    @Test
    void testSmartConfigurationControllerDynamicUrls() {
        FhirServerConfig config = new FhirServerConfig();
        ReflectionTestUtils.setField(config, "fhirBaseUrl", "https://mofapi.medicalofficeforce.co/fhir");

        SmartConfigurationController controller = new SmartConfigurationController();
        ReflectionTestUtils.setField(controller, "fhirServerConfig", config);

        Map<String, Object> smartConfig = controller.getSmartConfiguration();
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/authorize", smartConfig.get("authorization_endpoint"));
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/token", smartConfig.get("token_endpoint"));
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/introspect", smartConfig.get("introspection_endpoint"));
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir", smartConfig.get("issuer"));
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/jwks", smartConfig.get("jwks_uri"));
    }

    @Test
    void testOidcConfigurationControllerDynamicUrls() {
        FhirServerConfig config = new FhirServerConfig();
        ReflectionTestUtils.setField(config, "fhirBaseUrl", "https://mofapi.medicalofficeforce.co/fhir");

        OidcConfigurationController controller = new OidcConfigurationController();
        ReflectionTestUtils.setField(controller, "fhirServerConfig", config);

        Map<String, Object> oidcConfig = controller.getOidcConfiguration();
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/authorize", oidcConfig.get("authorization_endpoint"));
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/token", oidcConfig.get("token_endpoint"));
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir", oidcConfig.get("issuer"));
        Assertions.assertEquals("https://mofapi.medicalofficeforce.co/fhir/auth/jwks", oidcConfig.get("jwks_uri"));
    }
}
