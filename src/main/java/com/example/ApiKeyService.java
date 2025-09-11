package com.example;

import java.util.List;

public interface ApiKeyService {

    String create(String name, String principalName);

    void remove(String id);

    ApiKey findById(String id);

    List<ApiKey> list(String principalName);

}
