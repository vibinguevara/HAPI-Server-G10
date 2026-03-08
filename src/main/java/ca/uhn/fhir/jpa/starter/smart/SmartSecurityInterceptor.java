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
        if ("metadata".equals(theRequestDetails.getRequestPath())) {
            return;
        }

        // Allow API Documentation without auth
        if ("docs".equals(theRequestDetails.getRequestPath())) {
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

            theRequestDetails.getUserData().put("smart_scopes", scope);

            if (theRequestDetails.getRequestPath() != null && theRequestDetails.getRequestPath().endsWith("$export")) {
                if (scope == null || !(scope.contains("system/*.read") || scope.contains("system/*.*")
                        || scope.contains("system/*.rs") || scope.contains("system/*.r"))) {
                    throw new ForbiddenOperationException("insufficient_scope");
                }
            } else if (resourceName != null && operationType != null) {
                boolean isSinglePatientRequest = false;
                if (theRequestDetails.getId() != null) {
                    isSinglePatientRequest = true;
                } else if (theRequestDetails.getParameters() != null &&
                        (theRequestDetails.getParameters().containsKey("patient") ||
                                theRequestDetails.getParameters().containsKey("subject") ||
                                theRequestDetails.getParameters().containsKey("_id"))) {
                    isSinglePatientRequest = true;
                }
                validateScopes(scope, resourceName, operationType, isSinglePatientRequest);
            }

        } catch (AuthenticationException | ForbiddenOperationException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationException(
                    "Invalid token (" + e.getClass().getSimpleName() + "): " + e.getMessage());
        }
    }

    private void validateScopes(String scopes, String resource,
            ca.uhn.fhir.rest.api.RestOperationTypeEnum operationType, boolean isSinglePatientRequest) {
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
                if (!isSinglePatientRequest) {
                    if ("system".equals(scopePrefix)) {
                        return; // Authorized
                    }
                } else {
                    if ("system".equals(scopePrefix) || "patient".equals(scopePrefix) || "user".equals(scopePrefix)) {
                        return; // Authorized
                    }
                }
            }
        }

        throw new ForbiddenOperationException("insufficient_scope");
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
                return "read";
        }
    }

    @Hook(Pointcut.SERVER_OUTGOING_RESPONSE)
    public boolean outgoingResponse(RequestDetails theRequestDetails,
            ca.uhn.fhir.rest.api.server.ResponseDetails theResponseDetails) {
        org.hl7.fhir.instance.model.api.IBaseResource theResponse = theResponseDetails.getResponseResource();
        if (theResponse == null)
            return true;

        String scopes = (String) theRequestDetails.getUserData().get("smart_scopes");
        if (scopes == null)
            return true;

        boolean modified = false;
        if (theResponse instanceof org.hl7.fhir.r4.model.Bundle) {
            org.hl7.fhir.r4.model.Bundle bundle = (org.hl7.fhir.r4.model.Bundle) theResponse;
            java.util.Iterator<org.hl7.fhir.r4.model.Bundle.BundleEntryComponent> it = bundle.getEntry().iterator();
            while (it.hasNext()) {
                org.hl7.fhir.r4.model.Bundle.BundleEntryComponent entry = it.next();
                if (entry.getResource() != null) {
                    if (!isResourceAllowedByScopes(entry.getResource(), scopes)) {
                        it.remove();
                        modified = true;
                    }
                }
            }
            if (modified) {
                bundle.setTotal(bundle.getEntry().size());
            }
        } else if (theResponse instanceof org.hl7.fhir.r4.model.Condition
                || theResponse instanceof org.hl7.fhir.r4.model.Observation) {
            if (!isResourceAllowedByScopes(theResponse, scopes)) {
                // Return explicitly a forbidden operation exception for read operations on a
                // completely unauthorized resource
                throw new ForbiddenOperationException("Resource not permitted by granular scope");
            }
        }

        return true;
    }

    private boolean isResourceAllowedByScopes(org.hl7.fhir.instance.model.api.IBaseResource resource, String scopes) {
        if (resource instanceof org.hl7.fhir.r4.model.Condition) {
            org.hl7.fhir.r4.model.Condition cond = (org.hl7.fhir.r4.model.Condition) resource;
            boolean hasConditionGranular = false;
            boolean granularMatch = false;

            for (String scope : scopes.split(" ")) {
                if (scope.contains("Condition.") && scope.contains("?category=")) {
                    hasConditionGranular = true;
                    String categoryParam = scope.substring(scope.indexOf("?category=") + 10);

                    if (cond.getCategory() != null) {
                        for (org.hl7.fhir.r4.model.CodeableConcept category : cond.getCategory()) {
                            if (category.getCoding() != null) {
                                for (org.hl7.fhir.r4.model.Coding coding : category.getCoding()) {
                                    String resourceCategoryValue = coding.getSystem() + "|" + coding.getCode();
                                    if (coding.getSystem() == null || coding.getSystem().isBlank()) {
                                        resourceCategoryValue = coding.getCode();
                                    }
                                    if (categoryParam.equals(resourceCategoryValue)) {
                                        granularMatch = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else if (scope.contains("Condition.rs") && !scope.contains("?")) {
                    return true;
                } else if (scope.startsWith("user/*.") || scope.startsWith("patient/*.")
                        || scope.startsWith("system/*.")) {
                    if (scope.contains("*") || scope.contains("read") || scope.contains("rs")) {
                        return true;
                    }
                }
            }

            if (hasConditionGranular) {
                return granularMatch;
            }
            return true;
        } else if (resource instanceof org.hl7.fhir.r4.model.Observation) {
            org.hl7.fhir.r4.model.Observation obs = (org.hl7.fhir.r4.model.Observation) resource;
            boolean hasObservationGranular = false;
            boolean granularMatch = false;

            for (String scope : scopes.split(" ")) {
                if (scope.contains("Observation.") && scope.contains("?category=")) {
                    hasObservationGranular = true;
                    String categoryParam = scope.substring(scope.indexOf("?category=") + 10);

                    if (obs.getCategory() != null) {
                        for (org.hl7.fhir.r4.model.CodeableConcept category : obs.getCategory()) {
                            if (category.getCoding() != null) {
                                for (org.hl7.fhir.r4.model.Coding coding : category.getCoding()) {
                                    String resourceCategoryValue = coding.getSystem() + "|" + coding.getCode();
                                    if (coding.getSystem() == null || coding.getSystem().isBlank()) {
                                        resourceCategoryValue = coding.getCode();
                                    }
                                    if (categoryParam.equals(resourceCategoryValue)) {
                                        granularMatch = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else if (scope.contains("Observation.rs") && !scope.contains("?")) {
                    return true;
                } else if (scope.startsWith("user/*.") || scope.startsWith("patient/*.")
                        || scope.startsWith("system/*.")) {
                    if (scope.contains("*") || scope.contains("read") || scope.contains("rs")) {
                        return true;
                    }
                }
            }
            if (hasObservationGranular) {
                return granularMatch;
            }
            return true;
        }

        return true;
    }
}
