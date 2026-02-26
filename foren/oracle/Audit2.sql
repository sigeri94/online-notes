SET SERVEROUTPUT ON SIZE UNLIMITED

DECLARE
    v_sql   VARCHAR2(4000);
    v_count NUMBER;
BEGIN
    FOR t IN (
        SELECT table_name, column_name
        FROM dba_tab_columns
        WHERE owner = 'OPER'
    ) LOOP

        v_sql := 'SELECT COUNT(*) FROM OPER.' || t.table_name ||
                 ' WHERE "' || t.column_name || '" LIKE :1';

        BEGIN
            EXECUTE IMMEDIATE v_sql INTO v_count USING 'BSDROPR03';

            IF v_count > 0 THEN
                DBMS_OUTPUT.PUT_LINE('FOUND -> OPER.' || t.table_name || '.' || t.column_name);
            END IF;

        EXCEPTION
            WHEN OTHERS THEN NULL;
        END;

    END LOOP;
END;
/
