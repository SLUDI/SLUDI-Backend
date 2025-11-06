package org.example.repository;

import org.example.entity.Wallet;
import org.example.entity.WalletVerifiableCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface WalletVerifiableCredentialRepository extends JpaRepository<WalletVerifiableCredential, Long> {
    List<WalletVerifiableCredential> findAllByWallet(Wallet wallet);
}
