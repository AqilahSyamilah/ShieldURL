<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

date_default_timezone_set('Asia/Kuala_Lumpur');

class Database
{
    
    // // ===== LOCALHOST XAMPP =====
    // private $host = "127.0.0.1";
    // private $db_name = "shieldurl";
    // private $username = "root";
    // private $password = "";
    // private $port = 3306;
    
    // ===== VPS HOSTING =====
    
    private $host = "127.0.0.1";
    private $db_name = "shieldurl";
    private $username = "shieldurl_user";
    private $password = "ShieldURL@123";
    private $port = 3306;
    

    public $conn;

    public function getConnection()
    {
        $this->conn = null;

        try {
            $dsn = "mysql:host={$this->host};port={$this->port};dbname={$this->db_name};charset=utf8mb4";
            $this->conn = new PDO($dsn, $this->username, $this->password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
            $this->conn->exec("SET time_zone = '+08:00'");

            $this->setupDatabase();
            return $this->conn;
        } catch (PDOException $e) {
            die("Database connection failed: " . $e->getMessage());
        }
    }

    private function setupDatabase()
    {
        try {
            $this->conn->exec("CREATE DATABASE IF NOT EXISTS {$this->db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci");
        } catch (Exception $e) {
            // Database might already exist
        }

        $this->conn->exec("USE {$this->db_name}");
        $this->createTables();
        $this->upgradeDatabase();
    }

    private function createTables()
    {
        $queries = [];

        $queries[] = "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('admin','user') DEFAULT 'user',
            phone VARCHAR(20),
            department VARCHAR(50),
            is_active BOOLEAN DEFAULT TRUE,
            account_status ENUM('active','pending_first_login','inactive') DEFAULT 'active',
            force_password_change BOOLEAN DEFAULT FALSE,
            mfa_secret VARCHAR(64) NULL,
            mfa_required BOOLEAN DEFAULT FALSE,
            mfa_configured BOOLEAN DEFAULT FALSE,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP NULL,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB";

        // Combined standard schema with new Incident Response fields
        $queries[] = "CREATE TABLE IF NOT EXISTS url_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            url TEXT NOT NULL,
            status ENUM('safe','phishing','suspicious') DEFAULT 'safe',
            risk_level ENUM('low', 'medium', 'high') DEFAULT 'low',
            confidence_score FLOAT,
            features JSON,
            analysis_result TEXT,
            
            -- New Fields for Incident Response
            llm_summary TEXT,
            mitre_attack_json JSON,
            nist_response_json JSON,
            incident_response_text TEXT,
            user_advisory_text TEXT,
            pdf_report_path VARCHAR(255),
            
            matched_dataset BOOLEAN DEFAULT FALSE,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB";

        $queries[] = "CREATE TABLE IF NOT EXISTS user_activity (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            activity_type VARCHAR(50),
            description TEXT,
            ip_address VARCHAR(45),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB";

        $queries[] = "CREATE TABLE IF NOT EXISTS audit_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INT NULL,
            username VARCHAR(100),
            role VARCHAR(50),
            division VARCHAR(100),
            activity_type VARCHAR(80) NOT NULL,
            activity_details TEXT,
            ip_address VARCHAR(45),
            country VARCHAR(100),
            status VARCHAR(30) NOT NULL,
            session_id VARCHAR(128),
            INDEX idx_audit_timestamp (timestamp),
            INDEX idx_audit_activity (activity_type),
            INDEX idx_audit_division (division),
            INDEX idx_audit_country (country),
            INDEX idx_audit_user (user_id)
        ) ENGINE=InnoDB";

        $queries[] = "CREATE TABLE IF NOT EXISTS chat_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            scan_id INT NOT NULL,
            user_question TEXT NOT NULL,
            answer_status VARCHAR(50) NOT NULL,
            llm_latency_ms INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES url_logs(id) ON DELETE CASCADE
        ) ENGINE=InnoDB";

        foreach ($queries as $sql) {
            $this->conn->exec($sql);
        }

        $this->createDefaultAdmin();
    }

    private function upgradeDatabase()
    {
        // Attempt to add new columns if they don't exist (Quick migration for prototype)
        $alter_queries = [
            "ALTER TABLE url_logs ADD COLUMN IF NOT EXISTS risk_level ENUM('low', 'medium', 'high') DEFAULT 'low'",
            "ALTER TABLE url_logs ADD COLUMN IF NOT EXISTS llm_summary TEXT",
            "ALTER TABLE url_logs ADD COLUMN IF NOT EXISTS mitre_attack_json JSON",
            "ALTER TABLE url_logs ADD COLUMN IF NOT EXISTS nist_response_json JSON",
            "ALTER TABLE url_logs ADD COLUMN IF NOT EXISTS incident_response_text TEXT",
            "ALTER TABLE url_logs ADD COLUMN IF NOT EXISTS user_advisory_text TEXT",
            "ALTER TABLE url_logs ADD COLUMN IF NOT EXISTS pdf_report_path VARCHAR(255)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS account_status ENUM('active','pending_first_login','inactive') DEFAULT 'active'",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS force_password_change BOOLEAN DEFAULT FALSE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(64) NULL",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN DEFAULT FALSE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_configured BOOLEAN DEFAULT FALSE"
        ];

        foreach ($alter_queries as $sql) {
            try {
                // MySQL 8.0+ supports IF NOT EXISTS in ALTER. For older versions, this might fail if column exists.
                // We suppress errors for this prototype.
                @$this->conn->exec($sql);
            } catch (Exception $e) {
                // Ignore column exists error
            }
        }

        $this->addColumnIfMissing('users', 'account_status', "ENUM('active','pending_first_login','inactive') DEFAULT 'active'");
        $this->addColumnIfMissing('users', 'force_password_change', "BOOLEAN DEFAULT FALSE");
        $this->addColumnIfMissing('users', 'mfa_secret', "VARCHAR(64) NULL");
        $this->addColumnIfMissing('users', 'mfa_required', "BOOLEAN DEFAULT FALSE");
        $this->addColumnIfMissing('users', 'mfa_configured', "BOOLEAN DEFAULT FALSE");
    }

    private function addColumnIfMissing($table, $column, $definition)
    {
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) AS column_count
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?
        ");
        $stmt->execute([$this->db_name, $table, $column]);
        if ((int)$stmt->fetch()['column_count'] === 0) {
            $this->conn->exec("ALTER TABLE {$table} ADD COLUMN {$column} {$definition}");
        }
    }


    private function createDefaultAdmin()
    {
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE username='admin' LIMIT 1");
        $stmt->execute();

        if ($stmt->rowCount() === 0) {
            // password: admin123
            $hashed = password_hash("admin123", PASSWORD_DEFAULT);

            $stmt = $this->conn->prepare("
                INSERT INTO users (full_name, username, email, password, role, is_active)
                VALUES (?, ?, ?, ?, 'admin', TRUE)
            ");
            $stmt->execute([
                'System Administrator',
                'admin',
                'admin@shieldurl.com',
                $hashed
            ]);
        }
    }
}
