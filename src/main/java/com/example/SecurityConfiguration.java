package com.example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.web.http.CompositeHttpSessionIdResolver;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.HeaderHttpSessionIdResolver;
import org.springframework.session.web.http.HttpSessionIdResolver;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableRedisHttpSession
class SecurityConfiguration {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .csrf(CsrfConfigurer::disable)
                .cors(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                .csrf(CsrfConfigurer::disable)
                .cors(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowedMethods(List.of("*"));
        configuration.setAllowedHeaders(List.of("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    public JdbcOAuth2AuthorizationService oauth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository,
                                                                     SessionRepository<? extends Session> sessionRepository, Environment env) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository) {
            @Override
            public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
                Session session = sessionRepository.findById(token);
                if (session != null) {
                    SecurityContext context = session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
                    if (context != null) {
                        Authentication authentication = context.getAuthentication();
                        String username = authentication.getName();
                        String clientId = "mcp-client";
                        Set<String> scopes = Set.of("mcp");
                        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
                        if (client == null) {
                            return null;
                        }
                        Instant issuedAt = session.getCreationTime();
                        Instant expiresAt = Instant.now().plus(session.getMaxInactiveInterval());
                        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, issuedAt, expiresAt
                                .plus(Duration.ofDays(30)), scopes);
                        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client);
                        builder.token(accessToken, metadata -> {
                                    Map<String, Object> claims = Map.of(
                                            "sub", username,
                                            "aud", List.of(clientId),
                                            "nbf", issuedAt,
                                            "scope", String.join(",", scopes),
                                            "iss", env.getProperty("spring.security.oauth2.authorizationserver.issuer", ""),
                                            "jti", token
                                    );
                                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
                                }).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                .id(token).principalName(username).authorizedScopes(scopes);
                        return builder.build();
                    }
                }
                return super.findByToken(token, tokenType);
            }
        };
    }

    @Bean
    public JdbcOAuth2AuthorizationConsentService oauth2AuthorizationConsentService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
    }

    @Bean
    HttpSessionIdResolver httpSessionIdResolver() {
        return new CompositeHttpSessionIdResolver(HeaderHttpSessionIdResolver.xAuthToken(),
                new CookieHttpSessionIdResolver());
    }
}