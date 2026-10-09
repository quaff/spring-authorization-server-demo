package com.example;

import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class JdbcApiKeyService implements ApiKeyService {

    private static final String API_KEY_PREFIX = "ak-";

    private static final String COLUMN_NAMES = "id, name, principal_name, created_at";

    private static final String TABLE_NAME = "api_key";

    private static final String PK_FILTER = " WHERE id = :id";

    private static final String SAVE_SQL = "INSERT INTO " + TABLE_NAME
            + " (" + COLUMN_NAMES + ") VALUES (:id, :name, :principalName, :createdAt)";

    private static final String REMOVE_SQL = "DELETE FROM " + TABLE_NAME
            + PK_FILTER;

    private static final String FIND_BY_ID_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME
            + PK_FILTER;

    private static final String LIST_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME
            + " WHERE principal_name = :principalName ORDER BY created_at DESC";

    private final JdbcClient jdbcClient;

    public JdbcApiKeyService(JdbcOperations jdbcOperations) {
        this(JdbcClient.create(jdbcOperations));
    }

    public JdbcApiKeyService(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Override
    public String create(String name, String principalName) {
        String id = API_KEY_PREFIX + UUID.randomUUID().toString().replace("-", "");
        this.jdbcClient.sql(SAVE_SQL).params(Map.of("id", id, "name", name, "principalName", principalName, "createdAt", LocalDateTime.now())).update();
        return id;
    }

    @Override
    public void remove(String id) {
        this.jdbcClient.sql(REMOVE_SQL).param("id", id).update();
    }

    @Override
    public ApiKey findById(String id) {
        if (!id.startsWith(API_KEY_PREFIX)) {
            return null;
        }
        return this.jdbcClient.sql(FIND_BY_ID_SQL).param("id", id).query(new BeanPropertyRowMapper<>(ApiKey.class)).optional().orElse(null);
    }

    @Override
    public List<ApiKey> list(String principalName) {
        return this.jdbcClient.sql(LIST_SQL).param("principalName", principalName).query(new BeanPropertyRowMapper<>(ApiKey.class)).list();
    }
}
