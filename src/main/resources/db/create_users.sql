-- Auth-Server users table (MySQL 8)
-- Do NOT run this against ewayglobal.users — that table is a different schema.

CREATE DATABASE IF NOT EXISTS auth_service
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE auth_service;

CREATE TABLE IF NOT EXISTS users (
  id BIGINT NOT NULL AUTO_INCREMENT,
  username VARCHAR(100) NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'USER',
  PRIMARY KEY (id),
  UNIQUE KEY uk_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
