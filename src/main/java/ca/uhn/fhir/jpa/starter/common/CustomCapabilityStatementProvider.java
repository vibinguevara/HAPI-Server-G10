package ca.uhn.fhir.jpa.starter.common;

import ca.uhn.fhir.context.support.IValidationSupport;
import ca.uhn.fhir.jpa.api.config.JpaStorageSettings;
import ca.uhn.fhir.jpa.api.dao.IFhirSystemDao;
import ca.uhn.fhir.jpa.provider.JpaCapabilityStatementProvider;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.RestfulServer;
import ca.uhn.fhir.rest.server.util.ISearchParamRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.hl7.fhir.instance.model.api.IBaseConformance;
import org.hl7.fhir.r4.model.CapabilityStatement;
import org.hl7.fhir.r4.model.CanonicalType;

public class CustomCapabilityStatementProvider extends JpaCapabilityStatementProvider {

    public CustomCapabilityStatementProvider(RestfulServer theRestfulServer, IFhirSystemDao<?, ?> theSystemDao,
            JpaStorageSettings theStorageSettings, ISearchParamRegistry theSearchParamRegistry,
            IValidationSupport theValidationSupport) {
        super(theRestfulServer, theSystemDao, theStorageSettings, theSearchParamRegistry, theValidationSupport);
    }

    @Override
    public IBaseConformance getServerConformance(HttpServletRequest theRequest, RequestDetails theRequestDetails) {
        IBaseConformance conformance = super.getServerConformance(theRequest, theRequestDetails);

        if (conformance instanceof CapabilityStatement) {
            CapabilityStatement cs = (CapabilityStatement) conformance;
            cs.getInstantiates()
                    .add(new CanonicalType("http://hl7.org/fhir/uv/bulkdata/CapabilityStatement/bulk-data"));
            cs.getInstantiates()
                    .add(new CanonicalType("http://hl7.org/fhir/us/core/CapabilityStatement/us-core-server"));
        }

        return conformance;
    }
}
