package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ServiceBaseUrlBundleController {

    @GetMapping(value = "/service-base-url-bundle", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Resource> getServiceBaseUrlBundle() {
        Resource resource = new ClassPathResource("fhir-resources/singlePatientInfernoG10/service-url-fhir.json");
        if (resource.exists()) {
            return ResponseEntity.ok(resource);
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}
