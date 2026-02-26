package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class SmartStyleController {

	// This api should work without authorization as well
	// Similar to the SMART URL - this API should not need any authorization
    @GetMapping(value = "/smart-style.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> getSmartStyle() {
        Map<String, String> style = new HashMap<>();
        style.put("primaryColor", "#0A5EB0");
        style.put("secondaryColor", "#6c757d");
        style.put("backgroundColor", "#ffffff");
        style.put("logo", "https://api-uat.healthwealthsafe.link/images/mof_logo.png");

        return ResponseEntity.ok(style);
    }
}
