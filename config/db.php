<?php
session_start();

class Database
{
    private $host = "127.0.0.1";
    private $db_name = "shieldurl";
    private $username = "root";
    private $password = "";
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
            incident_response_text TEXT,
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
            "ALTER TABLE url_logs ADD COLUMN IF NOT EXISTS incident_response_text TEXT",
            "ALTER TABLE url_logs ADD COLUMN IF NOT EXISTS pdf_report_path VARCHAR(255)"
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
