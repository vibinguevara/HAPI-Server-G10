package ca.uhn.fhir.jpa.model.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Column;

import java.time.Instant;

@Entity
@Table(name = "smart_app_token")
public class SmartAppToken {

    @Id
    @Column(name = "jwt_id")
    private String jwtId;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "patient_id")
    private String patientId;

    @Column(name = "scope", length = 1000)
    private String scope;

    @Column(name = "issued_at")
    private Instant issuedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "revoked")
    private boolean revoked;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    // Constructors
    public SmartAppToken() {
    }

    public SmartAppToken(String jwtId, String clientId, String patientId, String scope, Instant issuedAt,
            Instant expiresAt) {
        this.jwtId = jwtId;
        this.clientId = clientId;
        this.patientId = patientId;
        this.scope = scope;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.revoked = false;
    }

    // Getters and Setters
    public String getJwtId() {
        return jwtId;
    }

    public void setJwtId(String jwtId) {
        this.jwtId = jwtId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getPatientId() {
        return patientId;
    }

    public void setPatientId(String patientId) {
        this.patientId = patientId;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt;
    }
}
