-- Combined MySQL dump: schema + sample data

-- Schema

-- (schema.sql content follows)

-- Database: `securechat`
-- This dump includes the schema and one sample user record for testing.

-- Run separately if needed:
-- CREATE DATABASE securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- USE securechat;

-- ----------------------------
-- Table structure for `users`
-- ----------------------------
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

-- ----------------------------
-- Table structure for `sessions`
-- ----------------------------
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

-- ----------------------------
-- Table structure for `audit_log`
-- ----------------------------
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

-- ----------------------------
-- Sample data
-- ----------------------------
-- Chosen sample account (credentials included for testing purposes):
-- Roll number: 22i-1095
-- Name: muhammad danish atif
-- Chosen password (for the sample account): Secur3P@ssw0rd!
-- The server stores SHA256(salt || password) where `salt` is 16 bytes.

-- Generated salt (hex): f1488d9dd395204692b677660158e717
-- Stored as MySQL binary literal x'...'

INSERT INTO users (email, username, salt, pwd_hash) VALUES (
  'student@example.edu',
  '22i-1095',
  x'f1488d9dd395204692b677660158e717',
  '9ff402dfc4a11b5d509662cca4bea2c79ce38c8010b42b9a4f3e3735d4788334'
);

-- End of dump

