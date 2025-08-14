package org.example.integration;

import org.example.dto.CitizenRegistrationDto;
import org.example.dto.HyperledgerTransactionResult;

public class HyperledgerService {
    public HyperledgerTransactionResult registerCitizen(CitizenRegistrationDto registration) {
        return null;
    }

    public String verifyCitizen(String didId, String verifierDid, String biometricType, String biometricHash, String challenge) {
        return null;
    }

    public void updateDID(String didId, String newPublicKey, String metadata) {

    }

    public void deactivateDID(String didId) {

    }
}
