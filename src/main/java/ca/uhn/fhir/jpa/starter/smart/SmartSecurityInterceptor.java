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

@Component
@Interceptor
public class SmartSecurityInterceptor {

    @Autowired
    private AuthService authService;

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

            // Skip non-resource scopes
            if (!scope.contains(".") || !scope.contains("/")) {
                continue;
            }

            String[] parts = scope.split("/");
            if (parts.length != 2)
                continue;

            String[] resourceAndAccess = parts[1].split("\\.");
            if (resourceAndAccess.length != 2)
                continue;

            String scopeResource = resourceAndAccess[0];
            String scopeAccess = resourceAndAccess[1];

            // Check if scope covers this resource/access
            boolean resourceMatch = scopeResource.equals("*") || scopeResource.equals(resource);

            // Check access match (wildcard, exact match, or granular suffix)
            boolean accessMatch = false;

            if (scopeAccess.equals("*") || scopeAccess.equals(requiredAccess)) {
                accessMatch = true;
            } else if (scopeAccess.length() > 0 && !scopeAccess.equals("read") && !scopeAccess.equals("write")) {
                // Granular scope check (c, r, u, d, s)
                // c=create, r=read, u=update, d=delete, s=search
                // read access requires 'r' or 's' (for search)
                // write access requires 'c', 'u', or 'd'

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
