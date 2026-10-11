package ca.uhn.fhir.jpa.starter.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Automatically loads key-value pairs from a .env file into the Spring environment
 * during application startup.
 */
public class DotenvEnvironmentPostProcessor implements EnvironmentPostProcessor {

    private static final Logger ourLog = LoggerFactory.getLogger(DotenvEnvironmentPostProcessor.class);

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        File envFile = findDotenvFile();
        if (envFile == null || !envFile.exists() || !envFile.isFile()) {
            ourLog.debug("No .env file found during environment post-processing.");
            return;
        }

        try {
            Map<String, Object> envProperties = new HashMap<>();
            List<String> lines = Files.readAllLines(envFile.toPath());
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
                    // Also expose lower-case dotted property equivalent if key is like FHIR_BASE_URL -> fhir.base-url
                    if ("FHIR_BASE_URL".equals(key)) {
                        envProperties.put("fhir.base-url", value);
                    }
                }
            }

            if (!envProperties.isEmpty()) {
                ourLog.info("Loaded {} environment properties from {}", envProperties.size(), envFile.getAbsolutePath());
                // Add with lower precedence than system environment variables so real OS env vars always win
                environment.getPropertySources().addLast(new MapPropertySource("dotenvProperties", envProperties));
            }
        } catch (IOException e) {
            ourLog.warn("Failed to load .env file from {}: {}", envFile.getAbsolutePath(), e.getMessage());
        }
    }

    private File findDotenvFile() {
        // 1. Current working directory
        File file = new File(".env");
        if (file.exists() && file.isFile()) {
            return file;
        }

        // 2. User directory system property
        String userDir = System.getProperty("user.dir");
        if (userDir != null) {
            file = new File(userDir, ".env");
            if (file.exists() && file.isFile()) {
                return file;
            }
        }

        return null;
    }
}
