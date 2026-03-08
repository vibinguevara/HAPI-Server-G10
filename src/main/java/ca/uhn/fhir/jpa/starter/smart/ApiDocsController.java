package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.util.StreamUtils;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;

@RestController
public class ApiDocsController {

    @GetMapping(value = "/docs", produces = MediaType.TEXT_HTML_VALUE)
    public String showApiDocs(HttpServletRequest request) {
        String baseUrl = org.springframework.web.servlet.support.ServletUriComponentsBuilder
                .fromRequestUri(request)
                .replacePath("/fhir")
                .build()
                .toUriString();

        try {
            ClassPathResource resource = new ClassPathResource("templates/api-docs.html");
            String html = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);

            // Minimal templating replacement for the references
            html = html.replace("<a th:href=\"${baseUrl}\" th:text=\"${baseUrl}\">https://example.com/fhir</a>",
                    "<a href=\"" + baseUrl + "\">" + baseUrl + "</a>");

            html = html.replace(
                    "<a th:href=\"${baseUrl} + '/metadata'\" target=\"_blank\" th:text=\"${baseUrl} + '/metadata'\">/metadata</a>",
                    "<a href=\"" + baseUrl + "/metadata\" target=\"_blank\">" + baseUrl + "/metadata</a>");

            html = html.replace(
                    "<a th:href=\"${baseUrl} + '/.well-known/smart-configuration'\" target=\"_blank\" th:text=\"${baseUrl} + '/.well-known/smart-configuration'\">/.well-known/smart-configuration</a>",
                    "<a href=\"" + baseUrl + "/.well-known/smart-configuration\" target=\"_blank\">" + baseUrl
                            + "/.well-known/smart-configuration</a>");

            return html;
        } catch (Exception e) {
            return "<html><body><h1>Error loading documentation</h1></body></html>";
        }
    }
}
