package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

@RestController
public class TokenController {

    @Autowired
    private AuthService authService;

    @PostMapping(value = "/auth/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> token(
            @RequestParam MultiValueMap<String, String> body // Capture all params
    ) {
        String grantType = body.getFirst("grant_type");
        String code = body.getFirst("code");
        String redirectUri = body.getFirst("redirect_uri");
        String codeVerifier = body.getFirst("code_verifier");

        if ("authorization_code".equals(grantType)) {
            AuthService.AuthData authData = authService.consumeAuthorizationCode(code);
            if (authData == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant"));
            }

            if (redirectUri != null && !redirectUri.equals(authData.getRedirectUri())) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "invalid_request", "error_description", "redirect_uri mismatch"));
            }

            // PKCE Validation
            if (authData.getCodeChallenge() != null) {
                if (codeVerifier == null) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "invalid_request", "error_description", "code_verifier required"));
                }
                if (!validatePkce(codeVerifier, authData.getCodeChallenge())) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "invalid_grant", "error_description", "PKCE verification failed"));
                }
            }

            Map<String, Object> tokenResponse = authService.generateTokens(authData);

            return ResponseEntity.ok()
                    .cacheControl(CacheControl.noStore())
                    .header("Pragma", "no-cache")
                    .body(tokenResponse);

        } else if ("refresh_token".equals(grantType)) {
            String refreshToken = body.getFirst("refresh_token");
            if (refreshToken == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "invalid_request", "error_description", "refresh_token required"));
            }
            AuthService.AuthData authData = authService.consumeRefreshToken(refreshToken);
            if (authData == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "invalid_grant", "error_description", "Invalid refresh token"));
            }

            // Handle scope if provided
            String scope = body.getFirst("scope");
            if (scope != null) {
                authData.setScope(scope);
            }

            Map<String, Object> tokenResponse = authService.generateTokens(authData);

            return ResponseEntity.ok()
                    .cacheControl(CacheControl.noStore())
                    .header("Pragma", "no-cache")
                    .body(tokenResponse);
        } else {
            return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));
        }
    }

    private boolean validatePkce(String verifier, String challenge) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            String calculated = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            return calculated.equals(challenge);
        } catch (Exception e) {
            return false;
        }
    }
}
