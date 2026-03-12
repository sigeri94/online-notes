-- =========================================================
-- File  : move_sawit_lab_tables.sql
-- Tujuan: Memindahkan tabel SAWIT_LAB dari USERS ke SAWIT_TBS
-- Oracle: 19c
-- =========================================================

SET ECHO ON
SET FEEDBACK ON
SET SERVEROUTPUT ON
SET PAGESIZE 200
SET LINESIZE 200

CREATE TABLESPACE SAWIT_APP
DATAFILE
  'D:\ORADATA\SAWITDB\sawit_app01.dbf'
SIZE 500M
AUTOEXTEND ON
NEXT 50M
MAXSIZE UNLIMITED
EXTENT MANAGEMENT LOCAL
SEGMENT SPACE MANAGEMENT AUTO;

ALTER USER SAWIT_LAB
QUOTA UNLIMITED ON SAWIT_APP;

PROMPT ==========================================
PROMPT 1. CEK TABLESPACE TUJUAN
PROMPT ==========================================

DECLARE
  v_cnt NUMBER;
BEGIN
  SELECT COUNT(*)
  INTO v_cnt
  FROM dba_tablespaces
  WHERE tablespace_name = 'SAWIT_APP';

  IF v_cnt = 0 THEN
    RAISE_APPLICATION_ERROR(-20001, 'TABLESPACE SAWIT_TBS TIDAK ADA');
  END IF;
END;
/
PROMPT TABLESPACE SAWIT_TBS OK
/

PROMPT ==========================================
PROMPT 2. PINDAHKAN TABEL
PROMPT ==========================================

ALTER TABLE SAWIT_LAB.KEBUN
MOVE TABLESPACE SAWIT_APP;

ALTER TABLE SAWIT_LAB.PETANI
MOVE TABLESPACE SAWIT_APP;

ALTER TABLE SAWIT_LAB.BLOK_KEBUN
MOVE TABLESPACE SAWIT_APP;

ALTER TABLE SAWIT_LAB.PRODUKSI_SAWIT
MOVE TABLESPACE SAWIT_APP;

PROMPT ==========================================
PROMPT 3. REBUILD INDEX (WAJIB)
PROMPT ==========================================

BEGIN
  FOR r IN (
    SELECT index_name
    FROM user_indexes
    WHERE table_name IN (
      'KEBUN',
      'PETANI',
      'BLOK_KEBUN',
      'PRODUKSI_SAWIT'
    )
  ) LOOP
    DBMS_OUTPUT.PUT_LINE('Rebuilding index: ' || r.index_name);
    EXECUTE IMMEDIATE
      'ALTER INDEX ' || r.index_name ||
      ' REBUILD TABLESPACE SAWIT_TBS';
  END LOOP;
END;
/
PROMPT INDEX REBUILD SELESAI
/

PROMPT ==========================================
PROMPT 4. PINDAHKAN LOB (JIKA ADA)
PROMPT ==========================================

DECLARE
  v_sql VARCHAR2(1000);
BEGIN
  FOR r IN (
    SELECT table_name, column_name
    FROM user_lobs
    WHERE table_name IN (
      'KEBUN',
      'PETANI',
      'BLOK_KEBUN',
      'PRODUKSI_SAWIT'
    )
  ) LOOP
    v_sql :=
      'ALTER TABLE SAWIT_LAB.' || r.table_name ||
      ' MOVE LOB (' || r.column_name || ') ' ||
      ' STORE AS (TABLESPACE SAWIT_TBS)';
    DBMS_OUTPUT.PUT_LINE(v_sql);
    EXECUTE IMMEDIATE v_sql;
  END LOOP;
END;
/
PROMPT LOB MOVE SELESAI
/

PROMPT ==========================================
PROMPT 5. VERIFIKASI HASIL
PROMPT ==========================================

COLUMN table_name FORMAT A20
COLUMN tablespace_name FORMAT A20

SELECT table_name, tablespace_name
FROM user_tables
WHERE table_name IN (
  'KEBUN',
  'PETANI',
  'BLOK_KEBUN',
  'PRODUKSI_SAWIT'
)
ORDER BY table_name;

PROMPT ==========================================
PROMPT 6. SET DEFAULT TABLESPACE USER
PROMPT ==========================================

ALTER USER SAWIT_LAB
DEFAULT TABLESPACE SAWIT_APP;

PROMPT ==========================================
PROMPT SELESAI - SEMUA TABEL TELAH DIPINDAHKAN
PROMPT ==========================================
