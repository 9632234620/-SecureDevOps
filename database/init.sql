CREATE DATABASE IF NOT EXISTS securedevops;

USE securedevops;

-- ============================================================
-- USERS TABLE
-- ============================================================

CREATE TABLE IF NOT EXISTS users (

    id INT AUTO_INCREMENT PRIMARY KEY,

    username VARCHAR(100) NOT NULL UNIQUE,

    email VARCHAR(150) NOT NULL UNIQUE,

    password VARCHAR(255) NOT NULL,

    role VARCHAR(50) DEFAULT 'viewer',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);


-- ============================================================
-- AUDIT LOGS TABLE
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_logs (

    id INT AUTO_INCREMENT PRIMARY KEY,

    username VARCHAR(100),

    action VARCHAR(100),

    status VARCHAR(50),

    ip_address VARCHAR(50),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);


-- ============================================================
-- DEPLOYMENTS TABLE
-- ============================================================

CREATE TABLE IF NOT EXISTS deployments (

    id INT AUTO_INCREMENT PRIMARY KEY,

    version VARCHAR(50),

    environment VARCHAR(50),

    status VARCHAR(50),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);