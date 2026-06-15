CREATE TABLE IF NOT EXISTS departments (
  id BIGINT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS employees (
  id BIGINT PRIMARY KEY,
  department_id BIGINT NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  phone VARCHAR(64),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_employees_department
    FOREIGN KEY (department_id) REFERENCES departments(id)
);

INSERT INTO departments (id, name)
VALUES
  (1, 'Engineering'),
  (2, 'Finance')
ON DUPLICATE KEY UPDATE name = VALUES(name);

INSERT INTO employees (id, department_id, full_name, email, phone)
VALUES
  (1, 1, 'Alice Example', 'alice@example.test', '555-0101'),
  (2, 2, 'Bob Example', 'bob@example.test', '555-0102')
ON DUPLICATE KEY UPDATE
  department_id = VALUES(department_id),
  full_name = VALUES(full_name),
  email = VALUES(email),
  phone = VALUES(phone);
