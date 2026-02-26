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
import java.util.List;
import java.util.Optional;
import java.time.Instant;
import com.nimbusds.jwt.SignedJWT;
import ca.uhn.fhir.jpa.model.entity.SmartAppToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
public class TokenController {

    private static final Logger ourLog = LoggerFactory.getLogger(TokenController.class);

    @Autowired
    private AuthService authService;

    @Autowired
    private SmartAppTokenRepository tokenRepository;

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
                ourLog.warn("Refresh token request failed: Invalid or revoked refresh token");
                return ResponseEntity.status(401)
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

    @PostMapping(value = "/auth/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> revokeToken(
            @RequestParam MultiValueMap<String, String> body) {
        ourLog.info("Received request to /auth/revoke with body: {}", body);
        String token = body.getFirst("token");
        if (token == null) {
            ourLog.warn("Revoke request failed: token is missing");
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "invalid_request", "error_description", "token is required"));
        }

        String clientId = null;
        String patientId = null;

        try {
            // Check if it's a JWT (Access Token)
            SignedJWT jwt = SignedJWT.parse(token);
            String jwtId = jwt.getJWTClaimsSet().getJWTID();
            Optional<SmartAppToken> dbToken = tokenRepository.findById(jwtId);
            if (dbToken.isPresent()) {
                clientId = dbToken.get().getClientId();
                patientId = dbToken.get().getPatientId();
            }
        } catch (Exception e) {
            // Not a valid JWT, maybe a refresh token. Let's look up in the tokenRepository
            // if we saved it?
            // Wait, we didn't save refresh tokens in the DB.
            // But we can check if it matches client_id and patient_id optionally provided?
            AuthService.AuthData rtData = authService.getRefreshTokenData(token);
            if (rtData != null) {
                clientId = rtData.getClientId();
                patientId = rtData.getPatientId();
            }
            ourLog.info(
                    "Token appears to be a refresh token, looking up by patient and client. Found clientId: {}, patientId: {}",
                    clientId, patientId);
        }

        // Check if the user passed client_id and patient_id directly (fallback if not
        // in token)
        if (clientId == null) {
            clientId = body.getFirst("client_id");
            patientId = body.getFirst("patient_id");
        }

        if (clientId != null) {

            authService.revokeRefreshTokens(clientId, patientId);
            ourLog.info("Revoked refresh tokens for client_id: {} and patient_id: {}", clientId, patientId);

            if (patientId != null) {
                List<SmartAppToken> activeTokens = tokenRepository.findByClientIdAndPatientId(clientId, patientId);
                for (SmartAppToken t : activeTokens) {
                    t.setRevoked(true);
                    t.setRevokedAt(Instant.now());
                    ourLog.info("Revoked access token for client_id: {} and patient_id: {}", clientId, patientId);
                }
                tokenRepository.saveAll(activeTokens);
            }
        }

        ourLog.info("Revoke request completed for token");
        // Return 200 OK as per RFC 7009 even if token not found
        return ResponseEntity.ok().build();
    }
}
