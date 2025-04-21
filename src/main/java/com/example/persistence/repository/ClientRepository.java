package com.example.persistence.repository;

import java.util.Optional;

import com.example.persistence.entity.Client;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientRepository extends JpaRepository<Client, String> {

	Optional<Client> findByClientId(String clientId);

}
