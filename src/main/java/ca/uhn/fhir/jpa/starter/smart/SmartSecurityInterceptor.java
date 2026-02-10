package ca.uhn.fhir.jpa.starter.smart;

import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
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

        } catch (Exception e) {
            throw new AuthenticationException("Invalid token: " + e.getMessage());
        }
    }
}
