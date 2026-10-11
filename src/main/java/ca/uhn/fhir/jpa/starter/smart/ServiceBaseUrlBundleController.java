package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@RestController
public class ServiceBaseUrlBundleController {

    @Autowired
    private FhirServerConfig fhirServerConfig;

    @GetMapping(value = "/service-base-url-bundle", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getServiceBaseUrlBundle() throws IOException {
        Resource resource = new ClassPathResource("fhir-resources/singlePatientInfernoG10/service-url-fhir.json");
        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }
        String content = new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String dynamicBaseUrl = fhirServerConfig.getFhirBaseUrl();
        // Replace hardcoded template URL with dynamic base URL
        content = content.replace("https://mofapi.medicalofficeforce.co/fhir", dynamicBaseUrl);
        return ResponseEntity.ok(content);
    }
}
