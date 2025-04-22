package com.example.persistence.repository;

import java.util.Optional;

import com.example.persistence.entity.Authorization;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorizationRepository extends JpaRepository<Authorization, String> {

	Optional<Authorization> findByState(String state);

	Optional<Authorization> findByAuthorizationCodeValue(String authorizationCode);

	Optional<Authorization> findByAccessTokenValue(String accessToken);

	Optional<Authorization> findByRefreshTokenValue(String refreshToken);

	Optional<Authorization> findByUserCodeValue(String userCode);

	Optional<Authorization> findByDeviceCodeValue(String deviceCode);

	@Query("select a from Authorization a where a.state = :token" +
			" or a.authorizationCodeValue = :token" +
			" or a.accessTokenValue = :token" +
			" or a.refreshTokenValue = :token" +
			" or a.userCodeValue = :token" +
			" or a.deviceCodeValue = :token"
	)
	Optional<Authorization> search(String token);

}