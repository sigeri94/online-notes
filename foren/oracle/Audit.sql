SET MARKUP CSV OFF

bagaimana memasukkan lebih dari 1
9609108
9609363
9609592
9608646
9608874
SET SERVEROUTPUT ON SIZE UNLIMITED

DECLARE
    v_sql    VARCHAR2(4000);
    v_count  NUMBER;

    TYPE t_list IS TABLE OF VARCHAR2(50);
    v_values t_list := t_list(
        '9609108',
        '9609363',
        '9609592',
        '9608646',
        '9608874'
    );

BEGIN
    FOR t IN (
        SELECT table_name, column_name
        FROM dba_tab_columns
        WHERE owner = 'OPER'
          AND data_type IN ('VARCHAR2','CHAR','CLOB')
    ) LOOP

        FOR i IN 1 .. v_values.COUNT LOOP

            v_sql := 'SELECT COUNT(*) FROM OPER.' || t.table_name ||
                     ' WHERE "' || t.column_name || '" LIKE :1';

            BEGIN
                EXECUTE IMMEDIATE v_sql
                    INTO v_count
                    USING '%' || v_values(i) || '%';

                IF v_count > 0 THEN
                    DBMS_OUTPUT.PUT_LINE(
                        'FOUND -> OPER.' ||
                        t.table_name || '.' ||
                        t.column_name || ' (VALUE=' ||
                        v_values(i) || ')'
                    );
                END IF;

            EXCEPTION
                WHEN OTHERS THEN NULL;
            END;

        END LOOP;

    END LOOP;
END;
/
