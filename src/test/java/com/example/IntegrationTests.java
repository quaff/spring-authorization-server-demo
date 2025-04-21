package com.example;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Map;

import static com.example.DatabaseInitializer.*;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class IntegrationTests {

    @LocalServerPort
    private int port;

    @Test
    void test() {
        RestClient restClient = restClient();

        // create access token
        Map<String, Object> result = restClient.post().uri("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(MultiValueMap.fromSingleValue(Map.of("grant_type", "client_credentials")))
                .retrieve().body(new ParameterizedTypeReference<>() {
                });
        assertThat(result).isNotNull();
        assertThat(result).containsEntry("token_type", "Bearer");
        assertThat(result).containsKey("access_token").containsKey("expires_in");
        String accessToken = (String) result.get("access_token");

        // introspect access token
        result = restClient.post().uri("/oauth2/introspect")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(MultiValueMap.fromSingleValue(Map.of("token", accessToken)))
                .retrieve().body(new ParameterizedTypeReference<>() {
                });
        assertThat(result).containsEntry("active", true);
        assertThat(result).containsEntry("token_type", "Bearer");
        assertThat(result).containsEntry("client_id", DEMO_CLIENT_ID);
        assertThat(result).containsEntry("sub", DEMO_CLIENT_ID);

        // revoke access token
        restClient.post().uri("/oauth2/revoke")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(MultiValueMap.fromSingleValue(Map.of("token", accessToken)))
                .retrieve().body(new ParameterizedTypeReference<>() {
                });
        result = restClient.post().uri("/oauth2/introspect")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(MultiValueMap.fromSingleValue(Map.of("token", accessToken)))
                .retrieve().body(new ParameterizedTypeReference<>() {
                });
        assertThat(result).containsEntry("active", false);
    }

    private RestClient restClient() {
        return RestClient.builder().baseUrl("http://localhost:" + port)
                .requestInterceptor(new BasicAuthenticationInterceptor(DEMO_CLIENT_ID, DEMO_CLIENT_SECRET))
                .build();
    }
}
