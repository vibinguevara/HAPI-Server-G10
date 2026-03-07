package ca.uhn.fhir.jpa.starter.smart;

import ca.uhn.fhir.jpa.model.entity.SmartAppRegistration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;
import java.util.UUID;

@org.springframework.web.bind.annotation.RestController
public class AppRegistrationController {

    @Autowired
    private SmartAppRegistrationRepository registrationRepository;

    @GetMapping(value = "/auth/register-app", produces = org.springframework.http.MediaType.TEXT_HTML_VALUE)
    public String showRegistrationForm() {
        return getHtmlPage(false, null, null, null);
    }

    @PostMapping(value = "/auth/register-app", produces = org.springframework.http.MediaType.TEXT_HTML_VALUE)
    public String registerApp(
            @RequestParam("appName") String appName,
            @RequestParam("redirectUris") String redirectUris,
            @RequestParam("allowedScopes") String allowedScopes,
            @RequestParam("appType") String appType) {

        SmartAppRegistration registration = new SmartAppRegistration();

        // Generate a random client ID
        String clientId = UUID.randomUUID().toString();
        registration.setClientId(clientId);

        // Generate a random client secret if confidential
        if ("confidential".equalsIgnoreCase(appType)) {
            registration.setClientSecret(UUID.randomUUID().toString());
        }

        registration.setAppName(appName);

        // Ensure no system scopes are registered (Inferno requirement for
        // single-patient apps)
        String safeScopes = allowedScopes.replaceAll("system/\\[\\w\\*\\.\\w\\]+", "").trim();
        registration.setAllowedScopes(safeScopes);

        registration.setRedirectUris(redirectUris);
        registration.setAppType(appType);
        registration.setCreatedAt(Instant.now());

        registrationRepository.save(registration);

        return getHtmlPage(true, registration.getClientId(), registration.getClientSecret(), registration.getAppName());
    }

    private String getHtmlPage(boolean success, String clientId, String clientSecret, String appName) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n");
        html.append("<html lang=\"en\">\n");
        html.append("<head>\n");
        html.append("    <meta charset=\"UTF-8\">\n");
        html.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("    <title>SMART App Registration</title>\n");
        html.append("    <style>\n");
        html.append(
                "        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; color: #333; }\n");
        html.append(
                "        .container { max-width: 600px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }\n");
        html.append("        h2 { margin-top: 0; color: #007bff; }\n");
        html.append("        label { display: block; margin: 10px 0 5px; font-weight: bold; }\n");
        html.append(
                "        input, select, button { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }\n");
        html.append(
                "        button { background-color: #007bff; color: white; border: none; cursor: pointer; font-size: 16px; }\n");
        html.append("        button:hover { background-color: #0056b3; }\n");
        html.append(
                "        .success-box { background-color: #d4edda; color: #155724; padding: 15px; border: 1px solid #c3e6cb; border-radius: 5px; margin-bottom: 20px; }\n");
        html.append(
                "        .hint { font-size: 0.85em; color: #666; margin-top: -10px; margin-bottom: 10px; display: block; }\n");
        html.append("    </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");
        html.append("    <div class=\"container\">\n");
        html.append("        <h2>Register SMART Application</h2>\n");

        if (success) {
            html.append("        <div class=\"success-box\">\n");
            html.append("            <h4>Application Registered Successfully!</h4>\n");
            html.append("            <p><strong>App Name:</strong> ").append(appName).append("</p>\n");
            html.append("            <p><strong>Client ID:</strong> <code>").append(clientId).append("</code></p>\n");
            if (clientSecret != null) {
                html.append("            <p><strong>Client Secret:</strong> <code>").append(clientSecret)
                        .append("</code></p>\n");
            }
            html.append(
                    "            <p style=\"color: red; font-size: 0.9em;\">Please save these credentials. You will not be able to see the secret again.</p>\n");
            html.append("        </div>\n");
        }

        html.append("        <form action=\"/auth/register-app\" method=\"post\">\n");
        html.append("            <label for=\"appName\">Application Name:</label>\n");
        html.append(
                "            <input type=\"text\" id=\"appName\" name=\"appName\" placeholder=\"e.g., My SMART Health App\" required>\n");
        html.append("            <label for=\"appType\">Application Type:</label>\n");
        html.append("            <select id=\"appType\" name=\"appType\" required>\n");
        html.append("                <option value=\"public\">Public (e.g., SPA, Mobile)</option>\n");
        html.append("                <option value=\"confidential\">Confidential (e.g., Web Server)</option>\n");
        html.append("            </select>\n");
        html.append("            <label for=\"redirectUris\">Redirect URIs:</label>\n");
        html.append(
                "            <span class=\"hint\">Comma-separated list (e.g., http://localhost/callback, https://myapp.com/callback)</span>\n");
        html.append(
                "            <input type=\"text\" id=\"redirectUris\" name=\"redirectUris\" placeholder=\"http://localhost:8080/callback\" required>\n");
        html.append("            <label for=\"allowedScopes\">Allowed Built-in Scopes:</label>\n");
        html.append(
                "            <span class=\"hint\">Space-separated list of scopes this app is allowed to request (patient-level only).</span>\n");
        html.append(
                "            <input type=\"text\" id=\"allowedScopes\" name=\"allowedScopes\" value=\"launch launch/patient patient/*.read openid fhirUser profile offline_access\" required>\n");
        html.append("            <button type=\"submit\">Register App</button>\n");
        html.append("        </form>\n");
        html.append("    </div>\n");
        html.append("</body>\n");
        html.append("</html>\n");
        return html.toString();
    }
}
