package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class AuthorizationController {

    @RequestMapping(value = "/auth/authorize", method = { RequestMethod.GET,
            RequestMethod.POST }, produces = "text/html")
    @ResponseBody
    public String authorize(
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("scope") String scope,
            @RequestParam("state") String state,
            @RequestParam(value = "aud", required = false) String aud,
            @RequestParam(value = "launch", required = false) String launch,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("code_challenge_method") String codeChallengeMethod) throws java.io.IOException {
        // Validate mandatory parameters
        if (!"code".equals(responseType)) {
            return "redirect:" + redirectUri + "?error=unsupported_response_type&state=" + state;
        }
        if (!"S256".equals(codeChallengeMethod)) {
            return "redirect:" + redirectUri + "?error=invalid_request&error_description=Only+S256+allowed&state="
                    + state;
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

        return html;
    }
}
