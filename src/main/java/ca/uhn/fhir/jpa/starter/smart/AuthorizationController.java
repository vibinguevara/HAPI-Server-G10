package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import java.net.URI;

@Controller
public class AuthorizationController {

    private static final String TRUSTED_AUD = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir";

    @RequestMapping(value = "/auth/authorize", method = { RequestMethod.GET,
            RequestMethod.POST })
    public ResponseEntity<String> authorize(
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("scope") String scope,
            @RequestParam("state") String state,
            @RequestParam(value = "aud", required = false) String aud,
            @RequestParam(value = "launch", required = false) String launch,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("code_challenge_method") String codeChallengeMethod) throws java.io.IOException {
        // Validate AUD Parameter strictly
        if (aud == null || !TRUSTED_AUD.equals(aud)) {
            String errorJson = "{\"error\": \"invalid_request\", \"error_description\": \"Invalid or missing aud parameter. Must match the trusted FHIR base URL exactly.\"}";
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(errorJson);
        }

        // Validate mandatory parameters
        if (!"code".equals(responseType)) {
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create(redirectUri + "?error=unsupported_response_type&state=" + state));
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        }
        if (!"S256".equals(codeChallengeMethod)) {
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI
                    .create(redirectUri + "?error=invalid_request&error_description=Only+S256+allowed&state=" + state));
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        }

        // Load the HTML template
        java.io.InputStream is = getClass().getResourceAsStream("/templates/consent.html");
        String html = new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);

        // Manual Placeholder Replacement
        html = html.replace("{{client_id}}", clientId);
        html = html.replace("{{redirect_uri}}", redirectUri);
        html = html.replace("{{state}}", state);
        html = html.replace("{{scope}}", scope);
        html = html.replace("{{code_challenge}}", codeChallenge);
        html = html.replace("{{code_challenge_method}}", codeChallengeMethod);
        html = html.replace("{{aud}}", aud != null ? aud : "");
        html = html.replace("{{launch}}", launch != null ? launch : "");

        // Simple scope checkbox generation
        StringBuilder scopesHtml = new StringBuilder();
        for (String s : scope.split(" ")) {
            scopesHtml.append("<div class='scope-item'><label>")
                    .append("<input type='checkbox' name='approved_scopes' value='").append(s)
                    .append("' checked='checked'/> ")
                    .append("<span>").append(s).append("</span>")
                    .append("</label></div>");
        }
        html = html.replace("{{scopes_list}}", scopesHtml.toString());

        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }
}
