package ca.uhn.fhir.jpa.starter.smart;

import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.exceptions.ForbiddenOperationException;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.util.Optional;
import ca.uhn.fhir.jpa.model.entity.SmartAppToken;

@Component
@Interceptor
public class SmartSecurityInterceptor {

    @Autowired
    private AuthService authService;

    @Autowired
    private SmartAppTokenRepository tokenRepository;

    @Hook(Pointcut.SERVER_INCOMING_REQUEST_PRE_HANDLED)
    public void incomingRequestPreHandled(RequestDetails theRequestDetails,
            jakarta.servlet.http.HttpServletRequest theServletRequest,
            jakarta.servlet.http.HttpServletResponse theServletResponse) {
        String authHeader = theRequestDetails.getHeader("Authorization");

        // Allow metadata without auth
        if (theRequestDetails.getRequestPath().equals("metadata")) {
            return;
        }

        // Allow .well-known endpoints (smart-configuration, openid-configuration)
        if (theRequestDetails.getRequestPath().startsWith(".well-known/")) {
            return;
        }

        // Also allow auth endpoints (though they are usually outside FHIR servlet,
        // better safe)
        if (theRequestDetails.getRequestPath().startsWith("auth/")) {
            return;
        }

        // Allow smart-style.json endpoint
        if (theRequestDetails.getRequestPath().equals("smart-style.json")) {
            return;
        }

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthenticationException("Missing or invalid Authorization header");
        }

        String token = authHeader.substring(7);
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            com.nimbusds.jose.JWSVerifier verifier = new com.nimbusds.jose.crypto.RSASSAVerifier(
                    (java.security.interfaces.RSAPublicKey) authService.getJwkSet().getKeys().get(0).toRSAKey()
                            .toPublicKey());

            if (!signedJWT.verify(verifier)) {
                throw new AuthenticationException("Invalid token signature");
            }

            if (signedJWT.getJWTClaimsSet().getExpirationTime().before(new java.util.Date())) {
                throw new AuthenticationException("Token expired");
            }

            // Database revocation check
            String jwtId = signedJWT.getJWTClaimsSet().getJWTID();
            if (jwtId == null) {
                throw new AuthenticationException("Token missing JWT ID");
            }
            Optional<SmartAppToken> dbToken = tokenRepository.findById(jwtId);
            if (dbToken.isEmpty()) {
                throw new AuthenticationException("Token not found in persistent storage");
            }
            if (dbToken.get().isRevoked()) {
                throw new AuthenticationException("Token has been revoked");
            }

            // Scope Validation
            Object scopeObj = signedJWT.getJWTClaimsSet().getClaim("scope");
            String resourceName = theRequestDetails.getResourceName();

            // Use RestOperationType for more accurate access type (Read vs Write)
            ca.uhn.fhir.rest.api.RestOperationTypeEnum operationType = theRequestDetails.getRestOperationType();

            String scope = null;
            if (scopeObj instanceof String) {
                scope = (String) scopeObj;
            } else if (scopeObj instanceof java.util.List) {
                scope = String.join(" ", (java.util.List<String>) scopeObj);
            }

            if (resourceName != null && operationType != null) {
                validateScopes(scope, resourceName, operationType);
            }

        } catch (AuthenticationException | ForbiddenOperationException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationException(
                    "Invalid token (" + e.getClass().getSimpleName() + "): " + e.getMessage());
        }
    }

    private void validateScopes(String scopes, String resource,
            ca.uhn.fhir.rest.api.RestOperationTypeEnum operationType) {
        if (scopes == null || scopes.isBlank()) {
            throw new ForbiddenOperationException("No scopes found provided in token");
        }

        String requiredAccess = getAccessType(operationType);

        // Debug info construction
        StringBuilder scopesFound = new StringBuilder();

        for (String scope : scopes.split(" ")) {
            if (scope.isBlank())
                continue;
            scopesFound.append(scope).append(" ");

            // Parse SMART v1 and v2 granular scopes
            // format: {patient|user|system}/{Resource|*}.{read|write|*|c|r|u|d|s}[?params]

            int firstSlash = scope.indexOf('/');
            if (firstSlash == -1)
                continue;

            String scopePrefix = scope.substring(0, firstSlash);
            String rest = scope.substring(firstSlash + 1);

            int firstDot = rest.indexOf('.');
            if (firstDot == -1) {
                // Not a granular scope like patient/Observation.read
                continue;
            }

            String scopeResource = rest.substring(0, firstDot);
            String accessAndParams = rest.substring(firstDot + 1);

            int firstQuestionMark = accessAndParams.indexOf('?');
            String scopeAccess = firstQuestionMark != -1
                    ? accessAndParams.substring(0, firstQuestionMark)
                    : accessAndParams;

            // Check if scope covers this resource/access
            boolean resourceMatch = scopeResource.equals("*") || scopeResource.equals(resource);

            // Check access match (wildcard, exact match, or granular suffix)
            boolean accessMatch = false;

            if (scopeAccess.equals("*") || scopeAccess.equals(requiredAccess)) {
                accessMatch = true;
            } else if (scopeAccess.length() > 0 && !scopeAccess.equals("read") && !scopeAccess.equals("write")) {
                // Granular scope check (c, r, u, d, s)
                if ("read".equals(requiredAccess)) {
                    accessMatch = scopeAccess.contains("r") || scopeAccess.contains("s");
                } else if ("write".equals(requiredAccess)) {
                    accessMatch = scopeAccess.contains("c") || scopeAccess.contains("u") || scopeAccess.contains("d");
                }
            }

            if (resourceMatch && accessMatch) {
                return; // Authorized
            }
        }

        throw new ForbiddenOperationException(
                "Insufficient scope for resource: " + resource + " during " + operationType + ". Required: "
                        + requiredAccess + ". Scopes found: [" + scopesFound.toString().trim() + "]");
    }

    private String getAccessType(ca.uhn.fhir.rest.api.RestOperationTypeEnum operationType) {
        switch (operationType) {
            case READ:
            case VREAD:
            case SEARCH_SYSTEM:
            case SEARCH_TYPE:
            case HISTORY_INSTANCE:
            case HISTORY_SYSTEM:
            case HISTORY_TYPE:
            case METADATA:
            case GRAPHQL_REQUEST:
                return "read";
            case CREATE:
            case UPDATE:
            case DELETE:
            case PATCH:
            case VALIDATE:
                return "write";
            default:
                // For EXTENDED_OPERATION_SERVER, EXTENDED_OPERATION_TYPE, etc. it depends.
                // Safest to default to 'read' or require specific handling?
                // Let's assume read for now.
                return "read";
        }
    }
}
