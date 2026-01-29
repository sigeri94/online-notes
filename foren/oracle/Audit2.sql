-- =========================================================
-- TARGETED FORENSIC SEARCH: DECEMBER 4, 2025
-- Excludes 'SELECT' to focus on Modification & Tampering
-- =========================================================
SET LINES 200
SET PAGES 5000
COLUMN dbusername FORMAT A15
COLUMN action_name FORMAT A20
COLUMN object_name FORMAT A25
COLUMN sql_text FORMAT A60

SELECT 
    TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS event_time,
    dbusername,
    userhost,
    action_name,
    object_schema,
    object_name,
    return_code, -- 0 means success, non-zero means failed attempt
    sql_text
FROM unified_audit_trail
WHERE event_timestamp >= TO_TIMESTAMP('2025-12-04 00:00:00', 'YYYY-MM-DD HH24:MI:SS')
  AND event_timestamp  < TO_TIMESTAMP('2025-12-05 00:00:00', 'YYYY-MM-DD HH24:MI:SS')
  AND action_name NOT IN ('SELECT', 'LOGON', 'LOGOFF') -- Focus on changes
ORDER BY event_timestamp ASC;

SELECT MIN(event_timestamp) as first_activity, dbusername, userhost
FROM unified_audit_trail
WHERE event_timestamp >= TO_TIMESTAMP('2025-12-04 00:00:00', 'YYYY-MM-DD HH24:MI:SS')
  AND action_name NOT IN ('SELECT', 'LOGON', 'LOGOFF')
GROUP BY dbusername, userhost;
