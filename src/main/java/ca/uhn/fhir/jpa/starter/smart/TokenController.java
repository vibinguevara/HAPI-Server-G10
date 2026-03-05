package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestHeader;
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
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam MultiValueMap<String, String> body // Capture all params
    ) {
        String grantType = body.getFirst("grant_type");
        String code = body.getFirst("code");
        String redirectUri = body.getFirst("redirect_uri");
        String codeVerifier = body.getFirst("code_verifier");

        // Extract client_id from body or Basic Auth header
        String clientId = body.getFirst("client_id");
        if (clientId == null && authHeader != null && authHeader.startsWith("Basic ")) {
            try {
                String base64Credentials = authHeader.substring("Basic ".length()).trim();
                byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
                String credentials = new String(credDecoded, StandardCharsets.UTF_8);
                // credentials = username:password
                final String[] values = credentials.split(":", 2);
                if (values.length > 0) {
                    clientId = values[0];
                }
            } catch (Exception e) {
                ourLog.warn("Failed to parse Basic Auth header for client_id", e);
            }
        }

        // If client authenticate using client_assertion (asymmetric client)
        String clientAssertionType = body.getFirst("client_assertion_type");
        String clientAssertion = body.getFirst("client_assertion");
        if (clientId == null && "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".equals(clientAssertionType)
                && clientAssertion != null) {
            String tokenEndpointUrl = org.springframework.web.servlet.support.ServletUriComponentsBuilder
                    .fromCurrentRequest().toUriString();
            clientId = authService.validateClientAssertion(clientAssertion, tokenEndpointUrl);
        }

        if ("authorization_code".equals(grantType)) {
            AuthService.AuthData authData = authService.consumeAuthorizationCode(code);
            if (authData == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant"));
            }

            if (clientId == null || !clientId.equals(authData.getClientId())) {
                ourLog.warn("Token exchange failed: client_id mismatch. Expected: {}, Got: {}", authData.getClientId(),
                        clientId);
                return ResponseEntity.status(401)
                        .body(Map.of("error", "invalid_client", "error_description", "Invalid client credentials"));
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
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "invalid_grant", "error_description", "Invalid refresh token"));
            }

            if (clientId == null || !clientId.equals(authData.getClientId())) {
                ourLog.warn("Refresh token exchange failed: client_id mismatch. Expected: {}, Got: {}",
                        authData.getClientId(), clientId);
                return ResponseEntity.status(401)
                        .body(Map.of("error", "invalid_client", "error_description", "Invalid client credentials"));
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
        } else if ("client_credentials".equals(grantType)) {
            String scope = body.getFirst("scope");

            if (clientAssertionType != null
                    && !"urn:ietf:params:oauth:client-assertion-type:jwt-bearer".equals(clientAssertionType)) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "invalid_request", "error_description", "Invalid client_assertion_type"));
            }

            if (clientId == null) {
                return ResponseEntity.status(401)
                        .body(Map.of("error", "invalid_client", "error_description",
                                "Invalid client assertion signature or claims"));
            }

            Map<String, Object> tokenResponse = authService.generateSystemTokens(clientId,
                    scope != null ? scope : "system/*.read");

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

    @PostMapping(value = "/auth/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> introspectToken(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam MultiValueMap<String, String> body) {
        ourLog.info("Received request to /auth/introspect");

        // Authenticate the client using Basic Auth or Form POST (confidential client)
        String clientId = body.getFirst("client_id");
        if (clientId == null && authHeader != null && authHeader.startsWith("Basic ")) {
            try {
                String base64Credentials = authHeader.substring("Basic ".length()).trim();
                byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
                String credentials = new String(credDecoded, StandardCharsets.UTF_8);
                // credentials = username:password
                final String[] values = credentials.split(":", 2);
                if (values.length > 0) {
                    clientId = values[0];
                }
            } catch (Exception e) {
                ourLog.warn("Failed to parse Basic Auth header for /auth/introspect client_id", e);
            }
        }

        if (clientId == null) {
            ourLog.warn("Introspect request failed: Missing or invalid client authentication");
            return ResponseEntity.status(401)
                    .body(Map.of("error", "invalid_client", "error_description", "Client authentication required"));
        }

        String token = body.getFirst("token");
        if (token == null) {
            ourLog.warn("Introspect request failed: token is missing");
            return ResponseEntity.ok().body(Map.of("active", false)); // 200 OK for proper auth but missing token
        }

        try {
            // First, try to parse it as a JWT to see if it's an access token
            SignedJWT jwt = SignedJWT.parse(token);
            String jwtId = jwt.getJWTClaimsSet().getJWTID();

            Optional<SmartAppToken> dbToken = tokenRepository.findById(jwtId);

            if (dbToken.isPresent() && !dbToken.get().isRevoked() &&
                    Instant.now().isBefore(dbToken.get().getExpiresAt())) {

                SmartAppToken activeToken = dbToken.get();
                // Ensure the client introspecting is the one who the token was issued to, if
                // required.
                if (!clientId.equals(activeToken.getClientId())) {
                    ourLog.warn("Introspect request failed: client_id mismatch. Expected: {}, Got: {}",
                            activeToken.getClientId(), clientId);
                    return ResponseEntity.ok().body(Map.of("active", false)); // If wrong client, act as if not active.
                }

                long exp = jwt.getJWTClaimsSet().getExpirationTime() != null
                        ? jwt.getJWTClaimsSet().getExpirationTime().toInstant().getEpochSecond()
                        : activeToken.getExpiresAt().getEpochSecond();

                long iat = jwt.getJWTClaimsSet().getIssueTime() != null
                        ? jwt.getJWTClaimsSet().getIssueTime().toInstant().getEpochSecond()
                        : activeToken.getIssuedAt().getEpochSecond();

                String sub = jwt.getJWTClaimsSet().getSubject() != null ? jwt.getJWTClaimsSet().getSubject()
                        : (activeToken.getPatientId() != null ? "Patient/" + activeToken.getPatientId() : "");

                Map<String, Object> responseMap = new java.util.HashMap<>();
                responseMap.put("active", true);
                responseMap.put("scope", activeToken.getScope() != null ? activeToken.getScope() : "");
                responseMap.put("client_id", activeToken.getClientId());
                responseMap.put("exp", exp);
                responseMap.put("iat", iat);

                if (jwt.getJWTClaimsSet().getIssuer() != null) {
                    responseMap.put("iss", jwt.getJWTClaimsSet().getIssuer());
                }

                if (jwt.getJWTClaimsSet().getClaim("id_token_sub") != null) {
                    responseMap.put("sub", jwt.getJWTClaimsSet().getStringClaim("id_token_sub"));
                } else if (!sub.isEmpty()) {
                    responseMap.put("sub", sub);
                }

                if (jwt.getJWTClaimsSet().getClaim("fhirUser") != null) {
                    responseMap.put("fhirUser", jwt.getJWTClaimsSet().getStringClaim("fhirUser"));
                }
                if (jwt.getJWTClaimsSet().getClaim("patient") != null) {
                    responseMap.put("patient", jwt.getJWTClaimsSet().getStringClaim("patient"));
                }
                if (jwt.getJWTClaimsSet().getClaim("encounter") != null) {
                    responseMap.put("encounter", jwt.getJWTClaimsSet().getStringClaim("encounter"));
                }

                return ResponseEntity.ok().body(responseMap);
            }
        } catch (Exception e) {
            // Not a valid JWT, or parsing failed.
            ourLog.debug("Token parsing or lookup failed during introspection", e);
        }

        // Token is invalid, expired, revoked, or not found.
        return ResponseEntity.ok().body(Map.of("active", false));
    }
}
