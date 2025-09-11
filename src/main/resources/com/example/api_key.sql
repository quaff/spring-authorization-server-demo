CREATE TABLE api_key (
    id varchar(100) NOT NULL,
    name varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    created_at timestamp DEFAULT NULL,
    PRIMARY KEY (id)
);
