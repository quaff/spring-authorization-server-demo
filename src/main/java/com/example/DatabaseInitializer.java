package com.example;

import com.example.persistence.entity.Client;
import com.example.persistence.repository.ClientRepository;
import com.example.oauth2.server.JpaRegisteredClientRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class DatabaseInitializer {

    public static final String DEMO_CLIENT_ID = "client-id";
    public static final String DEMO_CLIENT_SECRET = "client-secret";

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private JpaRegisteredClientRepository jpaRegisteredClientRepository;

    @PostConstruct
    void init() throws Exception {
        Client client = new Client();
        client.setClientId(DEMO_CLIENT_ID);
        client.setClientSecret("{noop}" + DEMO_CLIENT_SECRET);
        client.setClientName("Demo Client");
        client.setClientAuthenticationMethods("client_secret_basic");
        client.setAuthorizationGrantTypes("authorization_code,refresh_token,client_credentials");
        client.setRedirectUris("http://127.0.0.1:8080/authorized");
        client.setScopes("message:read,message:write");
        clientRepository.save(client);
    }
}
