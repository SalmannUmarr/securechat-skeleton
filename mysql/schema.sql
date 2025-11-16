-- MySQL Schema for Secure Chat System
-- Creates users table for registration and login

-- Create database (run separately if needed)
-- CREATE DATABASE securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- USE securechat;

-- Users table for authentication
-- Stores email, username, salt, and SHA256(salt || password)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL COMMENT 'User email address',
    username VARCHAR(255) UNIQUE NOT NULL COMMENT 'Username for login',
    salt VARBINARY(16) NOT NULL COMMENT 'Random salt for password hashing (16 bytes)',
    pwd_hash CHAR(64) NOT NULL COMMENT 'SHA256(salt || password) as hex string',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Account creation timestamp',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Last update timestamp',
    INDEX idx_email (email),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User accounts for secure chat';

-- Sessions table for tracking active sessions (optional, for audit)
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(64) UNIQUE NOT NULL COMMENT 'Session identifier',
    client_cert_fingerprint VARCHAR(64) NOT NULL COMMENT 'SHA256 fingerprint of client cert',
    server_cert_fingerprint VARCHAR(64) NOT NULL COMMENT 'SHA256 fingerprint of server cert',
    transcript_hash VARCHAR(64) COMMENT 'SHA256 hash of session transcript',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP NULL,
    message_count INT DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_token (session_token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Session audit log';

-- Audit log for connection attempts (security events)
CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL COMMENT 'login_success, login_failure, cert_invalid, etc.',
    email VARCHAR(255),
    client_cert_fingerprint VARCHAR(64),
    reason VARCHAR(255) COMMENT 'Detailed reason for security events',
    occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    INDEX idx_email (email),
    INDEX idx_type (event_type),
    INDEX idx_time (occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Security audit log for connection and authentication events';
