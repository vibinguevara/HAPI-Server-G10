package ca.uhn.fhir.jpa.starter.smart;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;

@Component
@Order(1) // Run early in the filter chain
public class SmartStyleFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if ("GET".equalsIgnoreCase(req.getMethod()) && req.getRequestURI().endsWith("/fhir/smart-style.json")) {
            res.setStatus(HttpServletResponse.SC_OK);
            res.setContentType("application/json");
            res.setCharacterEncoding("UTF-8");

            String json = "{" +
                    "\"primaryColor\": \"#0A5EB0\"," +
                    "\"secondaryColor\": \"#6c757d\"," +
                    "\"backgroundColor\": \"#ffffff\"," +
                    "\"logo\": \"https://api-uat.healthwealthsafe.link/images/mof_logo.png\"" +
                    "}";

            PrintWriter out = res.getWriter();
            out.print(json);
            out.flush();
            return;
        }

        chain.doFilter(request, response);
    }
}
