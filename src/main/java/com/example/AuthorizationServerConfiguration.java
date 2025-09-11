package com.example;

import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.session.Session;
import org.springframework.session.SessionIdGenerator;
import org.springframework.session.SessionRepository;
import org.springframework.session.UuidSessionIdGenerator;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.web.http.CompositeHttpSessionIdResolver;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.HeaderHttpSessionIdResolver;
import org.springframework.session.web.http.HttpSessionIdResolver;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames.*;

@Configuration
@EnableRedisHttpSession
class AuthorizationServerConfiguration {

    public static final String DEFAULT_CLIENT_ID = "mcp-client";

    private static final String SESSION_ID_PREFIX = "sid-";

    private final OAuth2AuthorizationServerProperties authorizationServerProperties;

    AuthorizationServerConfiguration(OAuth2AuthorizationServerProperties authorizationServerProperties) {
        this.authorizationServerProperties = authorizationServerProperties;
    }

    @Bean
    @Order(0)
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
    public JdbcRegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
        return new JdbcRegisteredClientRepository(jdbcOperations);
    }

    @Bean
    public JdbcOAuth2AuthorizationService oauth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository,
                                                                     SessionRepository<? extends Session> sessionRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository) {
            @Override
            public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
                if (tokenType == null || tokenType.equals(OAuth2TokenType.ACCESS_TOKEN)) {
                    if (token.startsWith(SESSION_ID_PREFIX)) {
                        Session session = sessionRepository.findById(token);
                        if (session != null) {
                            SecurityContext context = session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
                            if (context == null) {
                                return null;
                            }
                            Authentication authentication = context.getAuthentication();
                            if (authentication == null) {
                                return null;
                            }
                            String username = authentication.getName();
                            Set<String> scopes = authentication.getAuthorities().stream().filter(ga -> ga.getAuthority().startsWith("SCOPE_"))
                                    .map(ga -> ga.getAuthority().substring(6)).collect(Collectors.toSet());
                            RegisteredClient client = registeredClientRepository.findByClientId(DEFAULT_CLIENT_ID);
                            if (client == null) {
                                return null;
                            }
                            Instant issuedAt = session.getCreationTime();
                            Instant expiresAt = Instant.now().plus(session.getMaxInactiveInterval());
                            OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, issuedAt, expiresAt
                                    .plus(Duration.ofDays(30)), scopes);
                            OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client);
                            builder.token(accessToken, metadata -> {
                                        Map<String, Object> claims = new HashMap<>(Map.of(
                                                SUB, username,
                                                AUD, List.of(DEFAULT_CLIENT_ID),
                                                NBF, issuedAt,
                                                ISS, authorizationServerProperties.getIssuer(),
                                                JTI, token
                                        ));
                                        if (!scopes.isEmpty()) {
                                            claims.put("scope", String.join(" ", scopes));
                                        }
                                        Set<String> roles = authentication.getAuthorities().stream().filter(ga -> ga.getAuthority().startsWith("ROLE_"))
                                                .map(ga -> ga.getAuthority().substring(5)).collect(Collectors.toSet());
                                        if (!roles.isEmpty()) {
                                            claims.put("role", String.join(" ", roles));
                                        }
                                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
                                    }).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                    .id(token).principalName(username).authorizedScopes(scopes);
                            return builder.build();
                        }
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

    @Bean
    public SessionIdGenerator sessionIdGenerator() {
        return () -> SESSION_ID_PREFIX + UuidSessionIdGenerator.getInstance().generate().replaceAll("-", "");
    }
}