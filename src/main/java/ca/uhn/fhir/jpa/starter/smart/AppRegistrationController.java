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

                // Store the allowed scopes exactly as provided to support both
                // single-patient (patient/*.read) and multi-patient (system/*.read) apps.
                registration.setAllowedScopes(allowedScopes.trim());

                registration.setRedirectUris(redirectUris);
                registration.setAppType(appType);
                registration.setCreatedAt(Instant.now());

                registrationRepository.save(registration);

                return getHtmlPage(true, registration.getClientId(), registration.getClientSecret(),
                                registration.getAppName());
        }

        private String getHtmlPage(boolean success, String clientId, String clientSecret, String appName) {
                try {
                        org.springframework.core.io.Resource resource = new org.springframework.core.io.ClassPathResource("templates/register-app.html");
                        try (java.io.Reader reader = new java.io.InputStreamReader(resource.getInputStream(), java.nio.charset.StandardCharsets.UTF_8)) {
                                String html = org.springframework.util.FileCopyUtils.copyToString(reader);

                                if (success) {
                                        // Remove {{#if success}} tag
                                        html = html.replace("{{#if success}}", "");
                                        
                                        // Replace variables
                                        html = html.replace("{{appName}}", appName != null ? appName : "");
                                        html = html.replace("{{clientId}}", clientId != null ? clientId : "");
                                        
                                        // Handle clientSecret conditional
                                        if (clientSecret != null) {
                                                html = html.replace("{{#if clientSecret}}", "");
                                                html = html.replace("{{clientSecret}}", clientSecret);
                                                int idx = html.indexOf("{{/if}}");
                                                if (idx != -1) {
                                                        html = html.substring(0, idx) + html.substring(idx + "{{/if}}".length());
                                                }
                                        } else {
                                                int secStart = html.indexOf("{{#if clientSecret}}");
                                                int secEnd = html.indexOf("{{/if}}", secStart);
                                                if (secStart != -1 && secEnd != -1) {
                                                        html = html.substring(0, secStart) + html.substring(secEnd + "{{/if}}".length());
                                                }
                                        }
                                        
                                        // Remove remaining {{/if}} from success block
                                        int idx2 = html.indexOf("{{/if}}");
                                        if (idx2 != -1) {
                                                html = html.substring(0, idx2) + html.substring(idx2 + "{{/if}}".length());
                                        }
                                        return html;
                                } else {
                                        // Remove success block entirely
                                        int start = html.indexOf("{{#if success}}");
                                        int end = html.lastIndexOf("{{/if}}");
                                        if (start != -1 && end != -1) {
                                                html = html.substring(0, start) + html.substring(end + "{{/if}}".length());
                                        }
                                        return html;
                                }
                        }
                } catch (Exception e) {
                        e.printStackTrace();
                        return "<html><body><h2>Error loading template: " + e.getMessage() + "</h2></body></html>";
                }
        }
}
