package com.example;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerProperties;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.ClassUtils;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.List;

@SpringBootApplication
public class AuthorizationServerApplication {

    @Autowired
    OAuth2AuthorizationServerProperties authorizationServerProperties;

    @Autowired
    RegisteredClientRepository registeredClientRepository;

    @PostConstruct
    private void initialize() throws Exception {
        Class<?> clazz;
        try {
            clazz = ClassUtils.forName(
                    "org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerPropertiesMapper", //Spring Boot 4.0+
                    OAuth2AuthorizationServerProperties.class.getClassLoader());
        } catch (ClassNotFoundException ex) {
            clazz = ClassUtils.forName(
                    "org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerPropertiesMapper", //Spring Boot 3.x
                    OAuth2AuthorizationServerProperties.class.getClassLoader());
        }
        Constructor<?> ctor = clazz.getDeclaredConstructor(OAuth2AuthorizationServerProperties.class);
        ctor.setAccessible(true);
        Object instance = ctor.newInstance(authorizationServerProperties);
        Method method = clazz.getDeclaredMethod("asRegisteredClients");
        method.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<RegisteredClient> registeredClients = (List<RegisteredClient>) method.invoke(instance);
        for (RegisteredClient registeredClient : registeredClients) {
            if (registeredClientRepository.findByClientId(registeredClient.getClientId()) == null) {
                registeredClientRepository.save(registeredClient);
            }
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }


}
