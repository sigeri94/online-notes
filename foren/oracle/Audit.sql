-- =========================================================
-- ADVANCED ORACLE 19c FORENSIC SNAPSHOT SCRIPT
-- Purpose : Comprehensive Evidence Collection (IR/Forensics)
-- Version : 2.0
-- =========================================================
SET DEFINE OFF
SET VERIFY OFF
SET PAGES 50000
SET LINES 250
SET LONG 100000
SET TRIMSPOOL ON
SET FEEDBACK OFF
SET MARKUP HTML ON PREFORMAT ON

SPOOL oracle_comprehensive_forensics.html

PROMPT =====================================================
PROMPT 1. TEMPORAL & INSTANCE INTEGRITY
PROMPT =====================================================
-- Capturing DB time vs OS time to detect time manipulation
SELECT 
    TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS') AS db_sysdate,
    TO_CHAR(SYSTIMESTAMP, 'YYYY-MM-DD HH24:MI:SS.FF') AS db_timestamp,
    d.name AS db_name, 
    i.instance_name, 
    i.host_name, 
    i.startup_time 
FROM v$database d, v$instance i;

PROMPT =====================================================
PROMPT 2. AUDIT POLICY TAMPERING CHECK
PROMPT =====================================================
-- Check if auditing was disabled or modified recently
SELECT event_timestamp, dbusername, action_name, object_name, sql_text 
FROM unified_audit_trail 
WHERE action_name LIKE '%AUDIT%' 
   OR sql_text LIKE '%AUDIT%'
ORDER BY event_timestamp DESC;

-- Identify which policies are currently active
SELECT policy_name, enabled_opt, user_name FROM audit_unified_enabled_policies;

PROMPT =====================================================
PROMPT 3. PERSISTENCE & PRIVILEGE ESCALATION
PROMPT =====================================================
-- Check for newly created DBA users or sudden grant activities
SELECT event_timestamp, dbusername, action_name, target_user, sql_text 
FROM unified_audit_trail 
WHERE action_name IN ('GRANT ROLE', 'GRANT PRIVILEGE', 'CREATE USER', 'ALTER USER')
ORDER BY event_timestamp DESC;

-- Snapshot of current high-privilege users
SELECT grantee, granted_role FROM dba_role_privs 
WHERE granted_role IN ('DBA', 'SYSDBA', 'DATAPUMP_EXP_FULL_DATABASE')
UNION
SELECT grantee, privilege FROM dba_sys_privs 
WHERE privilege = 'UNLIMITED TABLESPACE' OR privilege LIKE '%ANY%';

PROMPT =====================================================
PROMPT 4. DATA EXFILTRATION & UNUSUAL ACCESS
PROMPT =====================================================
-- Check for Data Pump, Export, or large-scale SELECTs
SELECT event_timestamp, dbusername, userhost, action_name, sql_text 
FROM unified_audit_trail 
WHERE action_name IN ('EXPORT', 'DATAPUMP EXPORT')
   OR (action_name = 'SELECT' AND (object_name LIKE '%EMP%' OR object_name LIKE '%SALARY%' OR object_name LIKE '%CREDIT%'))
ORDER BY event_timestamp DESC;

-- Check for Database Links (Pivot point for lateral movement)
SELECT owner, db_link, host FROM dba_db_links;

PROMPT =====================================================
PROMPT 5. DESTRUCTIVE ACTIVITY (DDL)
PROMPT =====================================================
SELECT event_timestamp, dbusername, action_name, object_schema, object_name, sql_text 
FROM unified_audit_trail 
WHERE action_name IN ('DROP USER', 'DROP TABLE', 'TRUNCATE TABLE', 'PURGE RECYCLEBIN')
ORDER BY event_timestamp DESC;

PROMPT =====================================================
PROMPT 6. VOLATILE MEMORY ANALYSIS (SGA/SQL AREA)
PROMPT =====================================================
-- SQL that may not have been audited but is still in the Shared Pool
SELECT * FROM (
    SELECT parsing_schema_name, last_active_time, sql_text 
    FROM v$sql 
    WHERE parsing_schema_name NOT IN ('SYS', 'SYSTEM', 'DBSNMP')
    AND (sql_text LIKE '%DROP%' OR sql_text LIKE '%GRANT%' OR sql_text LIKE '%DELETE%')
    ORDER BY last_active_time DESC
) WHERE ROWNUM <= 50;

PROMPT =====================================================
PROMPT 7. SYSTEM ARTIFACTS LOCATION
PROMPT =====================================================
-- Identifying where physical logs reside for external analysis
SELECT name, value FROM v$parameter 
WHERE name IN ('audit_file_dest', 'background_dump_dest', 'user_dump_dest', 'core_dump_dest');

SPOOL OFF
SET MARKUP HTML OFF
SET FEEDBACK ON
