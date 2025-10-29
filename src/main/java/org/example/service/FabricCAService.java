package org.example.service;

import lombok.extern.slf4j.Slf4j;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.Properties;

@Slf4j
@Service
public class FabricCAService {

    private final String caUrl;
    private final String tlsCertPath;
    private final User caAdmin;
    private HFCAClient caClient;

    public FabricCAService(
            @Value("${fabric.ca.url}") String caUrl,
            @Value("${fabric.ca.tlsCertPath}") String tlsCertPath,
            User caAdmin
    ) {
        this.caUrl = caUrl;
        this.tlsCertPath = tlsCertPath;
        this.caAdmin = caAdmin;
    }

    @PostConstruct
    private void init() {
        try {
            Properties props = new Properties();
            if (tlsCertPath != null && !tlsCertPath.isEmpty()) {
                props.put("pemFile", tlsCertPath);
                props.put("allowAllHostNames", "true");
            }
            this.caClient = HFCAClient.createNewInstance(caUrl, props);
            this.caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            log.info("Fabric CA client initialized successfully at {}", caUrl);
        } catch (Exception e) {
            log.error("Fabric CA client init error: ", e);
            throw new RuntimeException("Fabric CA initialization failed", e);
        }
    }

    public String registerAndEnrollWithCsr(String enrollmentId, String affiliation, String csrPem) throws Exception {
        log.info("Registering and enrolling identity: {}", enrollmentId);

        RegistrationRequest registrationRequest = new RegistrationRequest(enrollmentId, affiliation);
        registrationRequest.setType("citizen-user");
        registrationRequest.setMaxEnrollments(-1);

        String enrollmentSecret = caClient.register(registrationRequest, caAdmin);
        log.info("Identity '{}' registered. Secret issued.", enrollmentId);

        EnrollmentRequest enrollmentRequest = new EnrollmentRequest();
        enrollmentRequest.setCsr(csrPem);

        Enrollment enrollment = caClient.enroll(enrollmentId, enrollmentSecret, enrollmentRequest);
        log.info("Identity '{}' enrolled. Certificate issued.", enrollmentId);

        return enrollment.getCert();
    }
}
