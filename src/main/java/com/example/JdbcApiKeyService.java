package com.example;

import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcOperations;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public class JdbcApiKeyService implements ApiKeyService {

    private static final String API_KEY_PREFIX = "ak-";

    private static final String COLUMN_NAMES = "id, name, principal_name, created_at";

    private static final String TABLE_NAME = "api_key";

    private static final String PK_FILTER = " WHERE id = ?";

    private static final String SAVE_SQL = "INSERT INTO " + TABLE_NAME
            + " (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?)";

    private static final String REMOVE_SQL = "DELETE FROM " + TABLE_NAME
            + PK_FILTER;

    private static final String FIND_BY_ID_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME
            + PK_FILTER;

    private static final String LIST_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME
            + " WHERE principal_name = ? ORDER BY created_at DESC";

    private final JdbcOperations jdbcOperations;

    public JdbcApiKeyService(JdbcOperations jdbcOperations) {
        this.jdbcOperations = jdbcOperations;
    }

    @Override
    public String create(String name, String principalName) {
        String id = API_KEY_PREFIX + UUID.randomUUID().toString().replaceAll("-", "");
        this.jdbcOperations.update(SAVE_SQL, id, name, principalName, LocalDateTime.now());
        return id;
    }

    @Override
    public void remove(String id) {
        this.jdbcOperations.update(REMOVE_SQL, id);
    }

    @Override
    public ApiKey findById(String id) {
        if (!id.startsWith(API_KEY_PREFIX)) {
            return null;
        }
        return this.jdbcOperations.queryForObject(FIND_BY_ID_SQL, new BeanPropertyRowMapper<>(ApiKey.class), id);
    }

    @Override
    public List<ApiKey> list(String principalName) {
        return this.jdbcOperations.query(LIST_SQL, new BeanPropertyRowMapper<>(ApiKey.class), principalName);
    }
}
