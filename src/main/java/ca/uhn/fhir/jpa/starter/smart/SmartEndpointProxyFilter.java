package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SmartEndpointProxyFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        String path = req.getRequestURI();
        String contextPath = req.getContextPath(); // usually empty or "/"

        // Check if path starts with /fhir/auth/ or /fhir/.well-known/
        // Need to handle potential context path
        String relativePath = path.substring(contextPath.length());

        if (relativePath.startsWith("/fhir/auth/") || relativePath.startsWith("/fhir/.well-known/")) {
            String newPath = relativePath.replaceFirst("/fhir", "");
            request.getRequestDispatcher(newPath).forward(request, response);
            return;
        }

        chain.doFilter(request, response);
    }
}
