package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
public class SmartConfigurationController {

    @Autowired
    private FhirServerConfig fhirServerConfig;

    @GetMapping("/.well-known/smart-configuration")
    public Map<String, Object> getSmartConfiguration() {
        Map<String, Object> config = new HashMap<>();
        config.put("authorization_endpoint", fhirServerConfig.getAuthorizeEndpoint());
        config.put("token_endpoint", fhirServerConfig.getTokenEndpoint());
        config.put("introspection_endpoint", fhirServerConfig.getIntrospectEndpoint());
        config.put("issuer", fhirServerConfig.getFhirBaseUrl());
        config.put("jwks_uri", fhirServerConfig.getJwksEndpoint());
                config.put("response_types_supported", Arrays.asList("code"));
                config.put("grant_types_supported", Arrays.asList("authorization_code"));
                config.put("token_endpoint_auth_methods_supported",
                                Arrays.asList("client_secret_basic", "client_secret_post"));
                config.put("scopes_supported",
                                Arrays.asList("openid", "profile", "fhirUser", "launch", "patient/*.read",
                                                "user/*.read", "offline_access"));
                config.put("capabilities", Arrays.asList(
                                "launch-ehr",
                                "launch-standalone",
                                "client-public",
                                "client-confidential-symmetric",
                                "client-confidential-asymmetric",
                                "context-ehr-patient",
                                "context-ehr-encounter",
                                "context-standalone-patient",
                                "permission-patient",
                                "permission-user",
                                "permission-offline",
                                "sso-openid-connect",
                                "permission-v1",
                                "permission-v2",
                                "authorize-post",
                                "context-banner",
                                "context-style"));
                config.put("code_challenge_methods_supported", Arrays.asList("S256"));

                return config;
        }
}
