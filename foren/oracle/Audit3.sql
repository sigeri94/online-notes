-- =========================================================
-- ORACLE 19c COMPREHENSIVE FORENSIC REPORT
-- Date Focus: 04-DEC-2025
-- Includes: System State, Privileges, & Activity Logs
-- =========================================================
SET DEFINE OFF
SET PAGES 50000
SET LINES 200
SET TRIMSPOOL ON
SET FEEDBACK OFF
SET MARKUP HTML ON PREFORMAT ON

SPOOL Full_Forensic_Report_Dec4.html

PROMPT =====================================================
PROMPT 1. DATABASE IDENTIFICATION & TIME SYNC
PROMPT =====================================================
SELECT name AS db_name, dbid, host_name, startup_time, 
       TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS') AS report_gen_time 
FROM v$database, v$instance;

PROMPT =====================================================
PROMPT 2. TARGETED ACTIVITY: 04 DESEMBER 2025 (NON-SELECT)
PROMPT =====================================================
-- Fokus pada DDL, DML, dan perubahan akun pada tanggal kejadian
SELECT 
    TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS event_time,
    dbusername, userhost, action_name, object_schema, object_name, 
    return_code, sql_text
FROM unified_audit_trail
WHERE event_timestamp >= TO_TIMESTAMP('2025-12-04 00:00:00', 'YYYY-MM-DD HH24:MI:SS')
  AND event_timestamp <  TO_TIMESTAMP('2025-12-05 00:00:00', 'YYYY-MM-DD HH24:MI:SS')
  AND action_name NOT IN ('SELECT', 'LOGON', 'LOGOFF')
ORDER BY event_timestamp ASC;

PROMPT =====================================================
PROMPT 3. CRITICAL SYSTEM PRIVILEGES (ANY PRIVS)
PROMPT =====================================================
SELECT PRIVILEGE, GRANTEE, ADMIN_OPTION 
FROM DBA_SYS_PRIVS 
WHERE PRIVILEGE LIKE '%ANY%' 
ORDER BY 1,2;

PROMPT =====================================================
PROMPT 4. HIGH PRIVILEGE ROLES (DBA/SYSDBA)
PROMPT =====================================================
SELECT * FROM DBA_ROLE_PRIVS 
WHERE GRANTED_ROLE IN ('DBA', 'SYSDBA', 'DATAPUMP_EXP_FULL_DATABASE')
ORDER BY 1;

PROMPT =====================================================
PROMPT 5. AUDIT POLICY INTEGRITY
PROMPT =====================================================
-- Cek apakah Unified Auditing aktif dan kebijakan apa yang berjalan
SELECT parameter, value FROM v$option WHERE parameter = 'Unified Auditing';

SELECT policy_name, enabled_opt, user_name 
FROM audit_unified_enabled_policies 
ORDER BY policy_name;

PROMPT =====================================================
PROMPT 6. USER ACCOUNT STATUS & RECENT CHANGES
PROMPT =====================================================
SELECT username, account_status, created, lock_date, expiry_date, profile 
FROM DBA_USERS 
ORDER BY created DESC;

PROMPT =====================================================
PROMPT 7. OBJECT TAMPERING CHECK (INVALID OBJECTS)
PROMPT =====================================================
SELECT owner, object_type, object_name, status 
FROM dba_objects 
WHERE status = 'INVALID' 
ORDER BY owner, object_type;

PROMPT =====================================================
PROMPT 8. VOLATILE MEMORY (RECENT SUSPICIOUS SQL)
PROMPT =====================================================
-- Mencari SQL berbahaya yang mungkin belum tertulis ke disk
SELECT parsing_schema_name, last_active_time, sql_text 
FROM v$sql 
WHERE (sql_text LIKE '%DROP%' OR sql_text LIKE '%GRANT%' OR sql_text LIKE '%TRUNCATE%')
  AND parsing_schema_name NOT IN ('SYS', 'SYSTEM')
ORDER BY last_active_time DESC;

SPOOL OFF
SET MARKUP HTML OFF
SET FEEDBACK ON
PROMPT Laporan Selesai: Full_Forensic_Report_Dec4.html
