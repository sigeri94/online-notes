-- ===================================================
-- Oracle Forensic Audit Template
-- Version: 1.0
-- Author: ChatGPT
-- ===================================================

-- ================================
-- 1. PARAMETER CONFIGURATION
-- ================================
-- Ganti sesuai kebutuhan
DEFINE FILTER_USER = 'HR_ADMIN';           -- Username Oracle
DEFINE FILTER_HOST = '172.16.0.10';       -- Host / machine
DEFINE START_DATE = TO_DATE('2026-01-01','YYYY-MM-DD');
DEFINE END_DATE   = TO_DATE('2026-01-07','YYYY-MM-DD');

-- ================================
-- 2. CURRENT SESSIONS
-- ================================
PROMPT ==== Current Active Sessions ====
SELECT
    SID,
    SERIAL#,
    USERNAME,
    OSUSER,
    MACHINE,
    PROGRAM,
    STATUS,
    LOGON_TIME
FROM V$SESSION
WHERE USERNAME = '&FILTER_USER'
   OR USERHOST = '&FILTER_HOST'
ORDER BY LOGON_TIME DESC;

-- ================================
-- 3. LOGIN / LOGOUT AUDIT
-- ================================
PROMPT ==== Login/Logout Audit ====
SELECT
    USERNAME,
    USERHOST,
    TO_CHAR(LOGON_TIME,'DD-MON-YYYY HH24:MI:SS') AS LOGIN_TIME,
    TO_CHAR(LOGOFF_TIME,'DD-MON-YYYY HH24:MI:SS') AS LOGOUT_TIME,
    LOGOFF_OPTION
FROM DBA_AUDIT_SESSION
WHERE (USERNAME = '&FILTER_USER' OR USERHOST = '&FILTER_HOST')
  AND LOGON_TIME BETWEEN &START_DATE AND &END_DATE
ORDER BY LOGON_TIME DESC;

-- ================================
-- 4. DML / DDL AUDIT
-- ================================
PROMPT ==== DML / DDL Audit ====
SELECT
    USERNAME,
    USERHOST,
    ACTION_NAME,
    OBJ_NAME,
    SQL_TEXT,
    TO_CHAR(TIMESTAMP,'DD-MON-YYYY HH24:MI:SS') AS TIME_EXECUTED
FROM DBA_AUDIT_TRAIL
WHERE (USERNAME = '&FILTER_USER' OR USERHOST = '&FILTER_HOST')
  AND TIMESTAMP BETWEEN &START_DATE AND &END_DATE
ORDER BY TIMESTAMP DESC;

-- ================================
-- 5. FINE-GRAINED AUDIT (FGA)
-- ================================
PROMPT ==== FGA Audit ====
SELECT
    DB_USER,
    OBJECT_SCHEMA,
    OBJECT_NAME,
    SQL_TEXT,
    TO_CHAR(EXTENDED_TIMESTAMP,'DD-MON-YYYY HH24:MI:SS') AS TIME_EXECUTED
FROM DBA_FGA_AUDIT_TRAIL
WHERE (DB_USER = '&FILTER_USER' OR OBJECT_SCHEMA = '&FILTER_HOST')
  AND EXTENDED_TIMESTAMP BETWEEN &START_DATE AND &END_DATE
ORDER BY EXTENDED_TIMESTAMP DESC;

-- ================================
-- 6. OPTIONAL: SEARCH FOR SUSPICIOUS QUERIES
-- ================================
PROMPT ==== Suspicious Queries (DROP/DELETE/UPDATE) ====
SELECT
    USERNAME,
    USERHOST,
    ACTION_NAME,
    SQL_TEXT,
    TO_CHAR(TIMESTAMP,'DD-MON-YYYY HH24:MI:SS') AS TIME_EXECUTED
FROM DBA_AUDIT_TRAIL
WHERE (USERNAME = '&FILTER_USER' OR USERHOST = '&FILTER_HOST')
  AND TIMESTAMP BETWEEN &START_DATE AND &END_DATE
  AND (UPPER(SQL_TEXT) LIKE '%DROP%' 
       OR UPPER(SQL_TEXT) LIKE '%DELETE%' 
       OR UPPER(SQL_TEXT) LIKE '%UPDATE%')
ORDER BY TIMESTAMP DESC;

-- ================================
-- END OF TEMPLATE
-- ================================
