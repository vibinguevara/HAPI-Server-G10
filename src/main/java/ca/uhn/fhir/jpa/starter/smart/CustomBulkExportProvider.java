package ca.uhn.fhir.jpa.starter.smart;

import ca.uhn.fhir.rest.annotation.IdParam;
import ca.uhn.fhir.rest.annotation.Operation;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.InvalidRequestException;
import jakarta.servlet.http.HttpServletResponse;
import org.hl7.fhir.r4.model.Group;
import org.hl7.fhir.r4.model.IdType;
import org.hl7.fhir.r4.model.Patient;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CustomBulkExportProvider {

    @Operation(name = "$export", global = true, idempotent = true, manualResponse = true, manualRequest = true)
    public void systemExport(RequestDetails theRequestDetails, HttpServletResponse theServletResponse)
            throws Exception {
        handleExport(theRequestDetails, theServletResponse);
    }

    @Operation(name = "$export", type = Group.class, idempotent = true, manualResponse = true, manualRequest = true)
    public void groupExport(@IdParam IdType theId, RequestDetails theRequestDetails,
            HttpServletResponse theServletResponse) throws Exception {
        handleExport(theRequestDetails, theServletResponse);
    }

    @Operation(name = "$export", type = Patient.class, idempotent = true, manualResponse = true, manualRequest = true)
    public void patientExport(RequestDetails theRequestDetails, HttpServletResponse theServletResponse)
            throws Exception {
        handleExport(theRequestDetails, theServletResponse);
    }

    private void handleExport(RequestDetails theRequestDetails, HttpServletResponse theServletResponse)
            throws Exception {
        String preferHeader = theRequestDetails.getHeader("Prefer");
        if (preferHeader == null || !preferHeader.contains("respond-async")) {
            throw new InvalidRequestException("Must include 'Prefer: respond-async' header.");
        }

        String jobId = UUID.randomUUID().toString();
        String originalRequestUrl = theRequestDetails.getCompleteUrl();

        String baseUrl = theRequestDetails.getFhirServerBase();
        String hostBase = baseUrl;
        if (hostBase.endsWith("/fhir")) {
            hostBase = hostBase.substring(0, hostBase.length() - 5);
        }

        String statusUrl = hostBase + "/bulk-status/" + jobId + "?req="
                + java.net.URLEncoder.encode(originalRequestUrl, "UTF-8");

        theServletResponse.setStatus(202);
        theServletResponse.setHeader("Content-Location", statusUrl);
        theServletResponse.getWriter().close();
    }
}
