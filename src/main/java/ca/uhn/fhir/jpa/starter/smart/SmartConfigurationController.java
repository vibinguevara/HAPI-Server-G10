package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
public class SmartConfigurationController {

        @GetMapping("/.well-known/smart-configuration")
        public Map<String, Object> getSmartConfiguration() {
                Map<String, Object> config = new HashMap<>();
                String baseUrl = "https://digressingly-auriferous-lee.ngrok-free.dev";// "https://localhost:8080"; //
                                                                                      // Using HTTPS as requested

                config.put("authorization_endpoint",
                                "https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/authorize");
                config.put("token_endpoint", "https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/token");
                config.put("issuer", "https://digressingly-auriferous-lee.ngrok-free.dev/fhir");
                config.put("jwks_uri", "https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/jwks");
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
                                "authorize-post"));
                config.put("code_challenge_methods_supported", Arrays.asList("S256"));

                return config;
        }
}
