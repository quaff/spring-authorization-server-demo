package com.example;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;

import static org.assertj.core.api.Assertions.assertThat;

@JdbcTest
public class JdbcApiKeyServiceTests {

    @Autowired
    ApiKeyService apiKeyService;

    @Test
    void crud() {
        String name = "name";
        String principalName = "username";
        String id = this.apiKeyService.create(name, principalName);
        assertThat(this.apiKeyService.findById(id)).extracting(ApiKey::getPrincipalName).isEqualTo(principalName);
        assertThat(this.apiKeyService.list(principalName)).element(0).extracting(ApiKey::getId).isEqualTo(id);
        this.apiKeyService.remove(id);
        assertThat(this.apiKeyService.list(principalName)).hasSize(0);
    }

    @Configuration
    static class Config {

        @Bean
        ApiKeyService apiKeyService(JdbcOperations jdbcOperations) {
            return new JdbcApiKeyService(jdbcOperations);
        }
    }
}
