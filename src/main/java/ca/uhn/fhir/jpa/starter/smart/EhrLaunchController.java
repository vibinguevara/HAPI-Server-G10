package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class EhrLaunchController {

    @Autowired
    private AuthService authService;

    @GetMapping("/auth/launch")
    public RedirectView initiateLaunch(
            @RequestParam("launch_url") String launchUrl,
            @RequestParam(value = "patient", required = false) String patientId) {

        // 1. Validate inputs
        if (patientId == null || patientId.isEmpty()) {
            patientId = "123"; // Default for testing
        }

        // 2. Generate Launch Token (Context)
        String launchToken = authService.generateLaunchContext(patientId);

        // 3. Construct Redirect URL
        // iss should be the FHIR base URL
        String iss = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir";

        String redirect = launchUrl + (launchUrl.contains("?") ? "&" : "?") +
                "iss=" + iss +
                "&launch=" + launchToken;

        return new RedirectView(redirect);
    }
}
