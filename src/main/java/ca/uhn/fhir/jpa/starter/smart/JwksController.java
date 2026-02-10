package ca.uhn.fhir.jpa.starter.smart;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JwksController {

    @Autowired
    private AuthService authService;

    @GetMapping("/auth/jwks")
    public Map<String, Object> keys() {
        return authService.getJwkSet().toJSONObject();
    }
}
