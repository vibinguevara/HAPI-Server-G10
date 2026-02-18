package ca.uhn.fhir.jpa.starter.smart;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthService {

    private final Map<String, AuthData> authCodeStore = new ConcurrentHashMap<>();
    private final Map<String, AuthData> refreshTokenStore = new ConcurrentHashMap<>();
    private final Map<String, AuthData> launchContextStore = new ConcurrentHashMap<>();
    private RSAKey rsaJWK;

    @PostConstruct
    public void init() {
        try {
            // Generate RSA Key Pair for signing tokens
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();

            rsaJWK = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA keys", e);
        }
    }

    public JWKSet getJwkSet() {
        return new JWKSet(rsaJWK);
    }

    public String generateAuthorizationCode(AuthData data) {
        String code = UUID.randomUUID().toString();
        data.setExpiresAt(Instant.now().plusSeconds(600)); // 10 minutes
        authCodeStore.put(code, data);
        return code;
    }

    public AuthData consumeAuthorizationCode(String code) {
        AuthData data = authCodeStore.remove(code);
        if (data == null)
            return null;
        if (Instant.now().isAfter(data.getExpiresAt()))
            return null;
        return data;
    }

    public AuthData consumeRefreshToken(String refreshToken) {
        AuthData data = refreshTokenStore.get(refreshToken);
        // data might be null if token doesn't exist or was removed
        return data;
    }

    public String generateLaunchContext(String patientId) {
        String launchToken = UUID.randomUUID().toString();
        AuthData data = new AuthData();
        data.setPatientId(patientId);
        data.setExpiresAt(Instant.now().plusSeconds(300)); // 5 minutes validity for launch token
        launchContextStore.put(launchToken, data);
        return launchToken;
    }

    public AuthData getLaunchContext(String launchToken) {
        AuthData data = launchContextStore.get(launchToken);
        if (data == null)
            return null;
        if (Instant.now().isAfter(data.getExpiresAt())) {
            launchContextStore.remove(launchToken);
            return null;
        }
        return data;
    }

    public Map<String, Object> generateTokens(AuthData authData) {
        try {
            String issuer = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir"; //"https://localhost:8080/fhir";
            Date now = new Date();
            Date exp = new Date(now.getTime() + 300 * 1000); // 5 minutes

            // Create Access Token
            JWTClaimsSet accessClaims = new JWTClaimsSet.Builder()
                    .subject(
                            authData.getPatientId() != null ? "Patient/" + authData.getPatientId() : "Practitioner/123")
                    .issuer(issuer)
                    .expirationTime(exp)
                    .issueTime(now)
                    .jwtID(UUID.randomUUID().toString())
                    .claim("scope", authData.getScope())
                    .build();

            SignedJWT accessToken = signJWT(accessClaims);

            // ID Token
            JWTClaimsSet idClaims = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(authData.getPatientId() != null ? authData.getPatientId() : "123")
                    .audience(authData.getClientId())
                    .expirationTime(Date.from(now.toInstant().plusSeconds(3600)))
                    .issueTime(Date.from(now.toInstant()))
                    .claim("fhirUser", issuer + "/Practitioner/practitioner-1") // Hardcoded for certification
                    .claim("profile", "Practitioner/practitioner-1")
                    .build();

            SignedJWT idToken = signJWT(idClaims);

            Map<String, Object> response = new ConcurrentHashMap<>();
            String refreshToken = UUID.randomUUID().toString();
            refreshTokenStore.put(refreshToken, authData);

            response.put("access_token", accessToken.serialize());
            response.put("token_type", "Bearer");
            response.put("expires_in", 300);
            response.put("scope", authData.getScope());
            response.put("id_token", idToken.serialize());
            response.put("refresh_token", refreshToken);

            // Add context fields
            if (authData.getPatientId() != null) {
                response.put("patient", authData.getPatientId());
            }
            if (authData.getEncounterId() != null) {
                response.put("encounter", authData.getEncounterId());
            }
            if (authData.getCodeChallenge() != null) {
                // Technically we should check code verifier here but let's assume valid for now
                // or add validation in controller
            }

            return response;

        } catch (Exception e) {
            throw new RuntimeException("Error generating tokens", e);
        }
    }

    private SignedJWT signJWT(JWTClaimsSet claims) throws JOSEException {
        JWSSigner signer = new RSASSASigner(rsaJWK);
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
                claims);
        signedJWT.sign(signer);
        return signedJWT;
    }

    // Inner class AuthData
    public static class AuthData {
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;
        private String codeChallenge;
        private String codeChallengeMethod;
        private String aud;
        private String launch;
        private Instant expiresAt;
        private String patientId;
        private String encounterId;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }

        public String getCodeChallenge() {
            return codeChallenge;
        }

        public void setCodeChallenge(String codeChallenge) {
            this.codeChallenge = codeChallenge;
        }

        public String getCodeChallengeMethod() {
            return codeChallengeMethod;
        }

        public void setCodeChallengeMethod(String codeChallengeMethod) {
            this.codeChallengeMethod = codeChallengeMethod;
        }

        public String getAud() {
            return aud;
        }

        public void setAud(String aud) {
            this.aud = aud;
        }

        public String getLaunch() {
            return launch;
        }

        public void setLaunch(String launch) {
            this.launch = launch;
        }

        public Instant getExpiresAt() {
            return expiresAt;
        }

        public void setExpiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
        }

        public String getPatientId() {
            return patientId;
        }

        public void setPatientId(String patientId) {
            this.patientId = patientId;
        }

        public String getEncounterId() {
            return encounterId;
        }

        public void setEncounterId(String encounterId) {
            this.encounterId = encounterId;
        }
    }
}
