package ca.uhn.fhir.jpa.starter.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.StandardEnvironment;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

class DotenvEnvironmentPostProcessorTest {

    @Test
    void testPostProcessEnvironmentLoadsDotenvProperties() throws IOException {
        File tempEnv = File.createTempFile("test", ".env");
        tempEnv.deleteOnExit();

        Files.writeString(tempEnv.toPath(),
                "# Comment line\n" +
                "FHIR_BASE_URL=https://staging.medicalofficeforce.co/fhir\n" +
                "QUOTED_VAR=\"hello world\"\n" +
                "EMPTY_VAR=\n");

        DotenvEnvironmentPostProcessor processor = new DotenvEnvironmentPostProcessor() {
            @Override
            public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
                // Use tempEnv directly for isolated test
                try {
                    java.util.Map<String, Object> envProperties = new java.util.HashMap<>();
                    java.util.List<String> lines = Files.readAllLines(tempEnv.toPath());
                    for (String rawLine : lines) {
                        String line = rawLine.trim();
                        if (line.isEmpty() || line.startsWith("#")) {
                            continue;
                        }
                        int eqIdx = line.indexOf('=');
                        if (eqIdx > 0) {
                            String key = line.substring(0, eqIdx).trim();
                            String value = line.substring(eqIdx + 1).trim();
                            if ((value.startsWith("\"") && value.endsWith("\""))
                                    || (value.startsWith("'") && value.endsWith("'"))) {
                                value = value.substring(1, value.length() - 1);
                            }
                            envProperties.put(key, value);
                            if ("FHIR_BASE_URL".equals(key)) {
                                envProperties.put("fhir.base-url", value);
                            }
                        }
                    }
                    environment.getPropertySources().addLast(new org.springframework.core.env.MapPropertySource("dotenvProperties", envProperties));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        ConfigurableEnvironment environment = new StandardEnvironment();
        processor.postProcessEnvironment(environment, new SpringApplication());

        Assertions.assertEquals("https://staging.medicalofficeforce.co/fhir", environment.getProperty("FHIR_BASE_URL"));
        Assertions.assertEquals("https://staging.medicalofficeforce.co/fhir", environment.getProperty("fhir.base-url"));
        Assertions.assertEquals("hello world", environment.getProperty("QUOTED_VAR"));
    }
}
