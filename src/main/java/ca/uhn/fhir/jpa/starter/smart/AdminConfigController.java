package ca.uhn.fhir.jpa.starter.smart;

import ca.uhn.fhir.jpa.model.entity.SystemConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

@RestController
public class AdminConfigController {

    @Autowired
    private SystemConfigurationRepository configRepository;

    public static final String REFRESH_TOKEN_LIFESPAN_KEY = "refresh_token_lifespan_days";
    public static final String DEFAULT_REFRESH_TOKEN_LIFESPAN = "0"; // 0 = never expire

    @GetMapping(value = "/admin/config", produces = MediaType.TEXT_HTML_VALUE)
    public String showConfigForm() {
        return renderHtmlPage(false);
    }

    @PostMapping(value = "/admin/config", produces = MediaType.TEXT_HTML_VALUE)
    public String saveConfig(@RequestParam("refreshTokenLifespan") String refreshTokenLifespan) {
        // Basic validation
        try {
            int days = Integer.parseInt(refreshTokenLifespan);
            if (days < 0)
                days = 0;

            SystemConfiguration config = new SystemConfiguration(REFRESH_TOKEN_LIFESPAN_KEY, String.valueOf(days));
            configRepository.save(config);

            return renderHtmlPage(true);
        } catch (NumberFormatException e) {
            return renderHtmlPage(false).replace("{SUCCESS_MESSAGE_PLACEHOLDER}",
                    "<div class=\"error-box\">Invalid number entered. Settings were not saved.</div>");
        }
    }

    private String renderHtmlPage(boolean success) {
        try {
            ClassPathResource resource = new ClassPathResource("templates/admin-config.html");
            String html = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);

            // Get current value from DB, default to 0 if not found
            Optional<SystemConfiguration> optionalConfig = configRepository.findById(REFRESH_TOKEN_LIFESPAN_KEY);
            String currentValue = optionalConfig.map(SystemConfiguration::getConfigValue)
                    .orElse(DEFAULT_REFRESH_TOKEN_LIFESPAN);

            html = html.replace("{LIFESPAN_VALUE}", currentValue);

            if (success) {
                html = html.replace("{SUCCESS_MESSAGE_PLACEHOLDER}",
                        "<div class=\"success-box\">Settings saved successfully!</div>");
            } else {
                html = html.replace("{SUCCESS_MESSAGE_PLACEHOLDER}", "");
            }

            return html;
        } catch (Exception e) {
            return "<html><body><h1>Error loading configuration page</h1></body></html>";
        }
    }
}
