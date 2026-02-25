package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
public class OidcConfigurationController {

    @GetMapping("/.well-known/openid-configuration")
    public Map<String, Object> getOidcConfiguration() {
        Map<String, Object> config = new HashMap<>();
        String issuer = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir";// "https://localhost:8080/fhir";

        config.put("issuer", issuer);
        config.put("jwks_uri", issuer + "/auth/jwks");
        config.put("authorization_endpoint", issuer + "/auth/authorize");
        config.put("token_endpoint", issuer + "/auth/token");
        config.put("userinfo_endpoint", issuer + "/Practitioner/example-1"); // Assuming fhirUser as userinfo for now

        config.put("id_token_signing_alg_values_supported", Arrays.asList("RS256"));
        config.put("response_types_supported", Arrays.asList("code"));
        config.put("subject_types_supported", Arrays.asList("public"));
        config.put("scopes_supported", Arrays.asList("openid", "fhirUser", "launch", "profile"));
        config.put("grant_types_supported", Arrays.asList("authorization_code"));
        config.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_post", "client_secret_basic")); // Basic
                                                                                                                         // list
        config.put("response_modes_supported", Arrays.asList("query"));

        return config;
    }

    @GetMapping("/smart-style.json")
    public Map<String, Object> getSmartStyle() {
        Map<String, Object> style = new HashMap<>();
        style.put("color_background", "#ffffff");
        style.put("color_error", "#b22222");
        style.put("color_highlight", "#ffff00");
        style.put("color_modal_backdrop", "#000000");
        style.put("color_success", "#008000");
        style.put("color_text", "#000000");
        style.put("dim_border_radius", "0");
        style.put("dim_font_size", "14px");
        style.put("dim_spacing_large", "24px");
        style.put("dim_spacing_medium", "16px");
        style.put("dim_spacing_small", "8px");
        style.put("font_family_body", "sans-serif");
        style.put("font_family_heading", "sans-serif");
        return style;
    }
}
