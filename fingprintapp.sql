-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jun 02, 2025 at 04:24 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `fingprintapp`
--

-- --------------------------------------------------------

--
-- Table structure for table `admin`
--

CREATE TABLE `admin` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admin`
--

INSERT INTO `admin` (`id`, `username`, `password`, `created_at`) VALUES
(1, 'admin', '$2y$10$MvG1Z8iK6te4StXLpTIN1OgBPpkl3qbHdlok55NMBEOQSU2xzP7MO', '2025-04-30 11:55:51');

-- --------------------------------------------------------

--
-- Table structure for table `admin_access_attempts`
--

CREATE TABLE `admin_access_attempts` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text NOT NULL,
  `device_details` text NOT NULL,
  `attempt_time` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admin_access_attempts`
--

INSERT INTO `admin_access_attempts` (`id`, `username`, `ip_address`, `user_agent`, `device_details`, `attempt_time`) VALUES
(1, 'admin', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36', '{\"browser\":\"Mozilla\\/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit\\/537.36 (KHTML, like Gecko) Chrome\\/137.0.0.0 Safari\\/537.36\",\"os\":\"Windows NT 10.0\",\"ip\":\"::1\",\"reason\":\"Concurrent session attempt\"}', '2025-06-01 20:24:39');

-- --------------------------------------------------------

--
-- Table structure for table `admin_alerts`
--

CREATE TABLE `admin_alerts` (
  `id` int(11) NOT NULL,
  `timestamp` datetime NOT NULL,
  `employee_id` int(11) DEFAULT NULL,
  `message` varchar(255) NOT NULL,
  `device_info` text DEFAULT NULL,
  `is_read` tinyint(1) NOT NULL DEFAULT 0,
  `severity` varchar(20) DEFAULT 'normal'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `admin_sessions`
--

CREATE TABLE `admin_sessions` (
  `id` int(11) NOT NULL,
  `session_id` varchar(255) NOT NULL,
  `admin_id` int(11) NOT NULL,
  `last_activity` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admin_sessions`
--

INSERT INTO `admin_sessions` (`id`, `session_id`, `admin_id`, `last_activity`, `created_at`) VALUES
(4, 'dedb61d8a102190904f7ebba76c20127', 1, '2025-06-01 23:28:28', '2025-06-01 23:02:21');

-- --------------------------------------------------------

--
-- Table structure for table `attendance`
--

CREATE TABLE `attendance` (
  `id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `date` date NOT NULL,
  `check_in` time DEFAULT NULL,
  `check_out` time DEFAULT NULL,
  `break_start` time DEFAULT NULL,
  `break_end` time DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `break_schedule`
--

CREATE TABLE `break_schedule` (
  `id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `break_start` time NOT NULL,
  `scheduled_end` time NOT NULL,
  `break_type` varchar(50) DEFAULT 'lunch',
  `actual_end` time DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `developers`
--

CREATE TABLE `developers` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `name` varchar(100) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `developers`
--

INSERT INTO `developers` (`id`, `username`, `password`, `name`, `created_at`) VALUES
(1, 'admin', '$2y$10$0rXRZThD5MDyixNDsuB/FOFiJHBRvi/zVLm7rpFNCRGpzVaTPXmyy', 'System Administrator', '2025-05-22 23:50:40');

-- --------------------------------------------------------

--
-- Table structure for table `developer_alerts`
--

CREATE TABLE `developer_alerts` (
  `id` int(11) NOT NULL,
  `message` varchar(255) NOT NULL,
  `created_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `employees`
--

CREATE TABLE `employees` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `role` varchar(20) DEFAULT 'employee',
  `password` varchar(255) NOT NULL,
  `is_verified` tinyint(1) DEFAULT 0,
  `admin_verified` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `sort_order` int(11) DEFAULT 0,
  `allowed_latitude` decimal(10,8) DEFAULT NULL,
  `allowed_longitude` decimal(11,8) DEFAULT NULL,
  `allowed_range_meters` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `employees`
--

INSERT INTO `employees` (`id`, `name`, `email`, `role`, `password`, `is_verified`, `admin_verified`, `created_at`, `sort_order`, `allowed_latitude`, `allowed_longitude`, `allowed_range_meters`) VALUES
(1, 'Ahmed Essam', 'godzilla@hotmail.net', 'employee', 'admin', 0, 0, '2025-05-26 23:08:14', 0, NULL, NULL, NULL),
(2, 'Employee 1', 'employee-12@hotmail.net', 'employee', '#Q4TKX4L', 0, 0, '2025-06-01 19:00:38', 0, NULL, NULL, NULL),
(3, 'Employee 2', 'employee-13@hotmail.net', 'employee', 'UH9232@1', 0, 0, '2025-06-01 19:00:41', 0, NULL, NULL, NULL),
(4, 'Employee 3', 'employee-88@hotmail.net', 'employee', 'NR7LGXWG', 0, 0, '2025-06-01 19:00:44', 0, NULL, NULL, NULL),
(5, 'Employee 4', 'employee-33@hotmail.net', 'employee', 'CMNVKOJ1', 0, 0, '2025-06-01 19:00:47', 0, NULL, NULL, NULL),
(6, 'Employee 5', 'employee-39@hotmail.net', 'employee', 'VI14OL*1', 0, 0, '2025-06-01 19:00:49', 0, NULL, NULL, NULL),
(7, 'Employee 6', 'employee-59@hotmail.net', 'employee', '@DTICEEH', 0, 0, '2025-06-01 19:00:53', 0, NULL, NULL, NULL),
(8, 'Employee 7', 'employee-69@hotmail.net', 'employee', 'VPSLFKPS', 0, 0, '2025-06-01 19:00:56', 0, NULL, NULL, NULL),
(10, 'Employee 8', 'employee-23@hotmail.net', 'employee', 'P#W@UTGQ', 0, 0, '2025-06-01 19:01:11', 0, NULL, NULL, NULL),
(11, 'Employee 9', 'employee-44@hotmail.net', 'employee', 'IPPHOLKH', 0, 0, '2025-06-01 19:01:14', 0, NULL, NULL, NULL),
(12, 'Employee 10', 'employee-53@hotmail.net', 'employee', 'ILFV2RM8', 0, 0, '2025-06-01 19:01:17', 0, NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `employee_tasks`
--

CREATE TABLE `employee_tasks` (
  `id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `task_description` text NOT NULL,
  `status` enum('pending','completed','in_progress') DEFAULT 'pending',
  `due_date` date DEFAULT NULL,
  `priority` enum('low','medium','high') DEFAULT 'medium',
  `created_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `completed_at` timestamp NULL DEFAULT NULL,
  `notes` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `fingerprints`
--

CREATE TABLE `fingerprints` (
  `id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `fingerprint_data` text NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `force_logout`
--

CREATE TABLE `force_logout` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `licenses`
--

CREATE TABLE `licenses` (
  `id` int(11) NOT NULL,
  `license_key` varchar(16) NOT NULL,
  `type` enum('admin','attendance') NOT NULL,
  `start_date` datetime NOT NULL,
  `end_date` datetime NOT NULL,
  `status` enum('active','expired','revoked','suspend') NOT NULL DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `licenses`
--

INSERT INTO `licenses` (`id`, `license_key`, `type`, `start_date`, `end_date`, `status`, `created_at`, `updated_at`) VALUES
(1, '0VUR-74TE-BMTY-T', 'admin', '2025-06-02 00:00:00', '2026-06-02 00:00:00', 'active', '2025-06-01 20:22:42', '2025-06-01 20:35:36');

-- --------------------------------------------------------

--
-- Table structure for table `license_activations`
--

CREATE TABLE `license_activations` (
  `id` int(11) NOT NULL,
  `license_key` varchar(255) NOT NULL,
  `activation_date` timestamp NOT NULL DEFAULT current_timestamp(),
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `license_activations`
--

INSERT INTO `license_activations` (`id`, `license_key`, `activation_date`, `ip_address`, `user_agent`) VALUES
(1, 'O3VR-KMJD-8LAQ-Y', '2025-06-01 20:11:38', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'),
(2, 'O3VR-KMJD-8LAQ-Y', '2025-06-01 20:20:01', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'),
(3, '0443-3IX&-1OOB-$', '2025-06-01 20:22:50', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'),
(4, '0VUR-74TE-BMTY-T', '2025-06-01 20:35:41', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36');

-- --------------------------------------------------------

--
-- Table structure for table `security_alerts`
--

CREATE TABLE `security_alerts` (
  `id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `alert_message` text NOT NULL,
  `severity` enum('low','medium','high') DEFAULT 'medium',
  `device_info` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `session_id`
--

CREATE TABLE `session_id` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `session_id` varchar(255) NOT NULL,
  `device_info` text DEFAULT NULL,
  `last_activity` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `session_id`
--

INSERT INTO `session_id` (`id`, `user_id`, `session_id`, `device_info`, `last_activity`) VALUES
(2, 1, '6779d6cd2b83666064c82e040cf6ee7c', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', '2025-06-01 23:17:07');

-- --------------------------------------------------------

--
-- Table structure for table `system_settings`
--

CREATE TABLE `system_settings` (
  `id` int(11) NOT NULL,
  `setting_key` varchar(100) NOT NULL,
  `setting_value` text NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

--
-- Dumping data for table `system_settings`
--

INSERT INTO `system_settings` (`id`, `setting_key`, `setting_value`, `created_at`, `updated_at`) VALUES
(1, 'admin_theme_color', 'red', '2025-05-23 03:57:30', '2025-06-01 23:37:38'),
(2, 'maintenance_mode', '0', '2025-05-28 16:48:15', '2025-05-28 16:48:24'),
(3, 'maintenance_reason', 'System maintenance in progress', '2025-05-28 16:48:15', '2025-05-28 16:48:15'),
(4, 'employee_theme_color', 'purple', '2025-06-01 21:30:38', '2025-06-01 22:18:29');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admin`
--
ALTER TABLE `admin`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `admin_access_attempts`
--
ALTER TABLE `admin_access_attempts`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `admin_alerts`
--
ALTER TABLE `admin_alerts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `employee_id` (`employee_id`),
  ADD KEY `timestamp` (`timestamp`),
  ADD KEY `is_read` (`is_read`);

--
-- Indexes for table `admin_sessions`
--
ALTER TABLE `admin_sessions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `admin_id` (`admin_id`);

--
-- Indexes for table `attendance`
--
ALTER TABLE `attendance`
  ADD PRIMARY KEY (`id`),
  ADD KEY `employee_id` (`employee_id`);

--
-- Indexes for table `break_schedule`
--
ALTER TABLE `break_schedule`
  ADD PRIMARY KEY (`id`),
  ADD KEY `employee_id` (`employee_id`);

--
-- Indexes for table `developers`
--
ALTER TABLE `developers`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `developer_alerts`
--
ALTER TABLE `developer_alerts`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `employees`
--
ALTER TABLE `employees`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- Indexes for table `employee_tasks`
--
ALTER TABLE `employee_tasks`
  ADD PRIMARY KEY (`id`),
  ADD KEY `employee_id` (`employee_id`);

--
-- Indexes for table `fingerprints`
--
ALTER TABLE `fingerprints`
  ADD PRIMARY KEY (`id`),
  ADD KEY `employee_id` (`employee_id`);

--
-- Indexes for table `force_logout`
--
ALTER TABLE `force_logout`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `licenses`
--
ALTER TABLE `licenses`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `license_key` (`license_key`),
  ADD KEY `idx_license_key` (`license_key`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_type` (`type`);

--
-- Indexes for table `license_activations`
--
ALTER TABLE `license_activations`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `security_alerts`
--
ALTER TABLE `security_alerts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `employee_id` (`employee_id`);

--
-- Indexes for table `session_id`
--
ALTER TABLE `session_id`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `system_settings`
--
ALTER TABLE `system_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `setting_key` (`setting_key`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admin`
--
ALTER TABLE `admin`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `admin_access_attempts`
--
ALTER TABLE `admin_access_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `admin_alerts`
--
ALTER TABLE `admin_alerts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `admin_sessions`
--
ALTER TABLE `admin_sessions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `attendance`
--
ALTER TABLE `attendance`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `break_schedule`
--
ALTER TABLE `break_schedule`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `developers`
--
ALTER TABLE `developers`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `developer_alerts`
--
ALTER TABLE `developer_alerts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `employees`
--
ALTER TABLE `employees`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT for table `employee_tasks`
--
ALTER TABLE `employee_tasks`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `fingerprints`
--
ALTER TABLE `fingerprints`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `force_logout`
--
ALTER TABLE `force_logout`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `licenses`
--
ALTER TABLE `licenses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `license_activations`
--
ALTER TABLE `license_activations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `security_alerts`
--
ALTER TABLE `security_alerts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `session_id`
--
ALTER TABLE `session_id`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `system_settings`
--
ALTER TABLE `system_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `admin_alerts`
--
ALTER TABLE `admin_alerts`
  ADD CONSTRAINT `fk_admin_alerts_employee` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `admin_sessions`
--
ALTER TABLE `admin_sessions`
  ADD CONSTRAINT `admin_sessions_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `admin` (`id`);

--
-- Constraints for table `attendance`
--
ALTER TABLE `attendance`
  ADD CONSTRAINT `attendance_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `break_schedule`
--
ALTER TABLE `break_schedule`
  ADD CONSTRAINT `break_schedule_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `employee_tasks`
--
ALTER TABLE `employee_tasks`
  ADD CONSTRAINT `employee_tasks_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `fingerprints`
--
ALTER TABLE `fingerprints`
  ADD CONSTRAINT `fingerprints_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `force_logout`
--
ALTER TABLE `force_logout`
  ADD CONSTRAINT `force_logout_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `employees` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `security_alerts`
--
ALTER TABLE `security_alerts`
  ADD CONSTRAINT `security_alerts_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `session_id`
--
ALTER TABLE `session_id`
  ADD CONSTRAINT `session_id_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `employees` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
