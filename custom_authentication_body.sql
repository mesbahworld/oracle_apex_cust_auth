create or replace PACKAGE BODY CUSTOM_AUTHENTICATION AS
  FUNCTION HASH_PASSWORD
    (p_username IN VARCHAR2,
     p_password IN VARCHAR2)
  RETURN VARCHAR2
  IS
    l_user          VARCHAR2(255) := UPPER(p_username);
    l_salt          VARCHAR2(255) := 'OJBEDGYTRBSVCHGWUHWGEYCHEG'; --DBMS_RANDOM.STRING('x', 32); -- Generate a random salt
    l_combined_str  VARCHAR2(4000);
    l_hashed_pass   VARCHAR2(4000);
  BEGIN
    -- Combine username, password, and salt
    l_combined_str := p_username || p_password || l_salt;

    -- Hash the combined string using SHA-512
    SELECT STANDARD_HASH(l_combined_str, 'SHA512')
    INTO l_hashed_pass
    FROM DUAL;

    RETURN l_hashed_pass;
  END HASH_PASSWORD;
--------------------------------------------------------------------------------------------------
--FUNCTION authenticate_user Over load without out parameter--------------------------------------
--------------------------------------------------------------------------------------------------
FUNCTION authenticate_user (
    p_username IN VARCHAR2,
    p_password IN VARCHAR2
    --p_auth_status_msg OUT VARCHAR2 
) RETURN BOOLEAN IS

    v_username        VARCHAR2(255) := upper(p_username);
    v_password        VARCHAR2(1000);
    v_hashed_password VARCHAR2(1000);
    v_count           NUMBER;
    v_password_valid  BOOLEAN := TRUE;
    v_failed_attempts NUMBER := 0;
	v_first_login     NUMBER(1,0);
    v_status          NUMBER(1,0);
    v_account_lock_date DATE;
    v_lock_remaining_time VARCHAR2(50);
    v_auth_status_msg VARCHAR2(1000);

BEGIN 
  -- Codes I normally use for AUTHENTICATION_RESULTS
  -- These get logged to the APEX Login Access Log.
  --  
  --    0    Normal, successful authentication 
  --    1    Unknown User Name 
  --    2    Account Locked 
  --    3    Account Expired 
  --    4    Incorrect Password 
  --    5    Password First Use 
  --    6    Maximum Login Attempts Exceeded 
  --    7    Unknown Internal Error 
  --    8    Password complexity requirements
  --   p_auth_status_msg := v_auth_status_msg; 
  -- First, check to see if the user exists

    IF p_username IS NULL THEN
    v_auth_status_msg := 'Username Can''t be blank';
	apex_util.set_authentication_result(7);
	apex_util.set_custom_auth_status(v_auth_status_msg);
	dbms_output.put_line(v_auth_status_msg);
    RETURN FALSE;
    ELSIF 
        p_password IS NULL THEN
        v_auth_status_msg := 'Password Can''t be blank';
		apex_util.set_authentication_result(1);
		apex_util.set_custom_auth_status(v_auth_status_msg);
		dbms_output.put_line(v_auth_status_msg);
        RETURN FALSE;
        -- Check if the username contains '@'
    ELSIF INSTR(p_username, '@') > 0 THEN
        dbms_output.put_line('Username contains @ symbol.');
        -- Handle the case where the username contains '@'
        BEGIN 
            SELECT  UPPER(username) into v_username  FROM all_users  WHERE upper(email) = UPPER(p_username);
            dbms_output.put_line('Username from Email: '||v_username);

            SELECT COUNT(*), failed_login_attempts , first_login, account_lock_date, status
            INTO v_count, v_failed_attempts, v_first_login, v_account_lock_date, v_status
            FROM all_users 
            WHERE upper(username) = v_username --  or upper(email) = v_username
            group by failed_login_attempts, first_login, account_lock_date, status;
            dbms_output.put_line('Username From Email: '||v_username||',v_count: '||v_count||',v_failed_attempts: '||v_failed_attempts||',v_first_login: '||v_first_login||',v_account_lock_date: '||v_account_lock_date||',v_status: '||v_status);

            EXCEPTION WHEN NO_DATA_FOUND THEN
            v_auth_status_msg := 'Unknown Email Address';
			apex_util.set_authentication_result(1);
			apex_util.set_custom_auth_status(v_auth_status_msg);
			dbms_output.put_line(v_auth_status_msg);
            RETURN FALSE;
        END;
        BEGIN
            SELECT COUNT(*), failed_login_attempts , first_login, account_lock_date, status
            INTO v_count, v_failed_attempts, v_first_login, v_account_lock_date, v_status
            FROM all_users 
            WHERE upper(username) = v_username --  or upper(email) = v_username
            group by failed_login_attempts, first_login, account_lock_date, status;

            EXCEPTION WHEN NO_DATA_FOUND THEN
            v_auth_status_msg := 'Unknown Username';
			apex_util.set_authentication_result(1);
            apex_util.set_custom_auth_status(v_auth_status_msg);
			dbms_output.put_line(v_auth_status_msg);
            RETURN FALSE; 
        END;
    ELSE
    dbms_output.put_line('Username Does not contains @ symbol.');
            BEGIN
            SELECT COUNT(*), failed_login_attempts , first_login, account_lock_date, status
            INTO v_count, v_failed_attempts, v_first_login, v_account_lock_date, v_status
            FROM all_users 
            WHERE upper(username) = v_username --  or upper(email) = v_username
            group by failed_login_attempts, first_login, account_lock_date, status;
            dbms_output.put_line('Username: '||v_username||',v_count: '||v_count||',v_failed_attempts: '||v_failed_attempts||',v_first_login: '||v_first_login||',v_account_lock_date: '||v_account_lock_date||',v_status: '||v_status);

            EXCEPTION WHEN NO_DATA_FOUND THEN
            v_auth_status_msg := 'Unknown Username';
			apex_util.set_authentication_result(1);
            apex_util.set_custom_auth_status(v_auth_status_msg);
			dbms_output.put_line(v_auth_status_msg);
            RETURN FALSE; 
        END;
    END IF;

    -- L 1 (First)
    IF v_count > 0 THEN
            -- L 1.1 (First)
            IF v_status <> 1 THEN 
                v_auth_status_msg := 'Account Disabled';
                apex_util.set_authentication_result(7);
                apex_util.set_custom_auth_status(v_auth_status_msg);
				dbms_output.put_line(v_auth_status_msg);
            RETURN FALSE;

            -- L 1.2
            ELSIF
            SYSDATE > v_account_lock_date THEN
            -- Reset failed login attempts
            UPDATE all_users SET FAILED_LOGIN_ATTEMPTS = 0
            WHERE upper(username) = v_username --  or upper(email) = v_username
            ;
            -- Add Locking Time
            UPDATE all_users SET account_lock_date = NULL
            WHERE upper(username) = v_username --  or upper(email) = v_username
            ;
            commit;
                        -- Hash the provided password
                        v_hashed_password := CUSTOM_AUTHENTICATION.hash_password(v_username, p_password);
                        dbms_output.put_line('v_hashed_password: '||v_hashed_password);
                        -- Get the stored password
                        dbms_output.put_line('Before v_password: '||v_password ||'-'|| v_username);
                        SELECT PASSWORD INTO v_password
                        FROM all_users
                        WHERE upper(USERNAME) = v_username --  or upper(email) = v_username
                        ;
                        dbms_output.put_line('v_password: '||v_password);

                        -- L 1.2.1 (First) Check if the account is locked  
                        IF v_failed_attempts >= dbms_custom_authentication.max_failed_login_attempts THEN
                        -- Remaining lock time 
                        SELECT ROUND((ACCOUNT_LOCK_DATE - SYSDATE)*1440)  into v_lock_remaining_time
                        FROM all_users
                        WHERE upper(USERNAME) = v_username --  or upper(email) = v_username
                        ;
                            -- Account Locked
							v_auth_status_msg := v_failed_attempts || ' Failed attempts, Account Locked! Please try again after '|| v_lock_remaining_time || ' minutes';
                            apex_util.set_authentication_result(2);
                            apex_util.set_custom_auth_status(v_auth_status_msg);
                            dbms_output.put_line(v_auth_status_msg);
                        RETURN FALSE;

                        -- L 1.2.2 -- Check if the account is expired
                        ELSIF v_account_lock_date >= SYSDATE AND ABS(v_account_lock_date - SYSDATE)*1440 <= LOCK_TIME  THEN 
                          -- Account Expired
						  v_auth_status_msg := 'Account Locked. Please try again after '|| v_lock_remaining_time || ' minutes';
                          apex_util.set_authentication_result(3);
                          apex_util.set_custom_auth_status(v_auth_status_msg);
                          dbms_output.put_line(v_auth_status_msg);
                        RETURN FALSE;

                        -- L 1.2.3 -- Compare passwords and RETURN result
                        ELSIF v_hashed_password = v_password THEN
                                    dbms_output.put_line('successful authentication');
                                    -- Reset failed login attempts
                                    UPDATE all_users SET FAILED_LOGIN_ATTEMPTS = 0
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    -- Add Locking Time
                                    UPDATE all_users SET account_lock_date = NULL
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    commit;
									-- Normal, successful authentication
									v_auth_status_msg :=  'User:'||p_username||' is back.';
                                    apex_util.set_authentication_result(0);
                                    APEX_UTIL.SET_CUSTOM_AUTH_STATUS(v_auth_status_msg);
                                    dbms_output.put_line(v_auth_status_msg);
                                    RETURN TRUE;
                        -- L 1.2.4 (last)
                        ELSE
                        -- Increment failed login attempts
                        UPDATE all_users SET FAILED_LOGIN_ATTEMPTS = v_failed_attempts + 1
                        WHERE upper(username) = v_username --  or upper(email) = v_username
                        ;
                        commit;
                                    -- L 1.2.4.1 (First and Last)
									IF v_failed_attempts >= dbms_custom_authentication.max_failed_login_attempts-1 THEN
                                    -- Add Locking Time
                                    UPDATE all_users SET account_lock_date = SYSDATE + NUMTODSINTERVAL(LOCK_TIME, 'MINUTE')
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    commit; 
									v_auth_status_msg :=  'Password did not match.(ERR-L 1.2.4.1)';
									apex_util.set_authentication_result(4);
                                    apex_util.set_custom_auth_status(v_auth_status_msg);
									dbms_output.put_line(v_auth_status_msg);
									RETURN FALSE;
                                    END IF;	
                        -- Incorrect Password
						v_auth_status_msg :=  'Password did not match.(ERR-L 1.2.4)';     
                        apex_util.set_authentication_result(4);
                        apex_util.set_custom_auth_status(v_auth_status_msg);
						dbms_output.put_line(v_auth_status_msg);
						RETURN FALSE; 
                        END IF;
            -- L 1.3 (Last)
            ELSE
                        -- Hash the provided password
                        v_hashed_password := CUSTOM_AUTHENTICATION.hash_password(v_username, p_password);
                        dbms_output.put_line('v_hashed_password: '||v_hashed_password);
                        -- Get the stored password
                        dbms_output.put_line('Before v_password: '||v_password ||'-'|| v_username);
                        SELECT PASSWORD INTO v_password
                        FROM all_users
                        WHERE upper(USERNAME) = v_username --  or upper(email) = v_username
                        ;
                        dbms_output.put_line('v_password: '||v_password);

                        -- L 1.3.1 (First) Check if the account is locked  
                        IF v_failed_attempts >= dbms_custom_authentication.max_failed_login_attempts THEN
                        -- Remaining lock time 
                        SELECT ROUND((ACCOUNT_LOCK_DATE - SYSDATE)*1440)  into v_lock_remaining_time
                        FROM all_users
                        WHERE upper(USERNAME) = v_username --  or upper(email) = v_username
                        ;
                            -- Account Locked
                            v_auth_status_msg := v_failed_attempts || ' Failed attempts, Account Locked! Please try again after '|| v_lock_remaining_time || ' minutes';
							apex_util.set_authentication_result(2);
                            apex_util.set_custom_auth_status(v_auth_status_msg);
                            dbms_output.put_line(v_auth_status_msg);
                        RETURN FALSE;

                        -- L 1.3.2 -- Check if the account is expired
                        ELSIF v_account_lock_date >= SYSDATE AND ABS(v_account_lock_date - SYSDATE)*1440 <= LOCK_TIME  THEN 
                          -- Account Expired
                          v_auth_status_msg := 'Account Locked. Please try again after '|| v_lock_remaining_time || ' minutes';
						  apex_util.set_authentication_result(3);
                          apex_util.set_custom_auth_status(v_auth_status_msg);
						  dbms_output.put_line(v_auth_status_msg);
                        RETURN FALSE;

                        -- L 1.3.3 -- Compare passwords and RETURN result
                        ELSIF v_hashed_password = v_password THEN

                                    -- Reset failed login attempts
                                    UPDATE all_users SET FAILED_LOGIN_ATTEMPTS = 0
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    -- Add Locking Time
                                    UPDATE all_users SET account_lock_date = NULL
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    commit;
                                    dbms_output.put_line('Update faield login attempts');
									-- Normal, successful authentication
                                    v_auth_status_msg :=  'User:'||p_username||' is back.';
									apex_util.set_authentication_result(0);
									apex_util.set_custom_auth_status(v_auth_status_msg);
                                    dbms_output.put_line(v_auth_status_msg);
                                    RETURN TRUE;
                        -- L 1.3.4 (Last)
                        ELSE
                        -- Increment failed login attempts
                        UPDATE all_users SET FAILED_LOGIN_ATTEMPTS = v_failed_attempts + 1
                        WHERE upper(username) = v_username --  or upper(email) = v_username
                        ;
                        commit;
                                    -- L 1.3.4.1 (First and Last)
									IF v_failed_attempts >= dbms_custom_authentication.max_failed_login_attempts-1 THEN
                                    -- Add Locking Time
                                    UPDATE all_users SET account_lock_date = SYSDATE + NUMTODSINTERVAL(LOCK_TIME, 'MINUTE')
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    commit;
									v_auth_status_msg :=  'Password did not match.(ERR-L 1.3.4.1)';
                                    apex_util.set_authentication_result(4);
                                    apex_util.set_custom_auth_status(v_auth_status_msg);
									dbms_output.put_line(v_auth_status_msg);
									RETURN FALSE;
                                    END IF;	
                        -- Incorrect Password
                        v_auth_status_msg :=  'Password did not match.(ERR-L 1.3.4)';
                        apex_util.set_authentication_result(4);
                        apex_util.set_custom_auth_status(v_auth_status_msg);
						dbms_output.put_line(v_auth_status_msg);

						RETURN FALSE; 
                        END IF;
            END IF;
    -- L 2 (Last)
    ELSE
            -- The username does not exist
            v_auth_status_msg :=  'Unknown User Name.'||v_username;
            apex_util.set_authentication_result(1); -- Unknown User Name
            apex_util.set_custom_auth_status(v_auth_status_msg);
			dbms_output.put_line(v_auth_status_msg);
            RETURN FALSE;
    END IF;

EXCEPTION
    WHEN OTHERS THEN
        -- Log an unknown internal error
        v_auth_status_msg :=  'Unknown Authentication-'|| sqlerrm;
        apex_util.set_authentication_result(7); -- Unknown Internal Error
        apex_util.set_custom_auth_status(v_auth_status_msg);
		dbms_output.put_line(v_auth_status_msg);
        RETURN FALSE;
END authenticate_user;
--------------------------------------------------------------------------------------------------
--FUNCTION authenticate_user Over load with out parameter--------------------------------------
--------------------------------------------------------------------------------------------------
FUNCTION authenticate_user (
    p_username IN VARCHAR2,
    p_password IN VARCHAR2,
    p_auth_status_msg OUT VARCHAR2 
) RETURN BOOLEAN IS

    v_username        VARCHAR2(255) := upper(p_username);
    v_password        VARCHAR2(1000);
    v_hashed_password VARCHAR2(1000);
    v_count           NUMBER;
    v_password_valid  BOOLEAN := TRUE;
    v_failed_attempts NUMBER := 0;
	v_first_login     NUMBER(1,0);
    v_status          NUMBER(1,0);
    v_account_lock_date DATE;
    v_lock_remaining_time VARCHAR2(50);
    v_auth_status_msg VARCHAR2(1000);

BEGIN 
  -- Codes I normally use for AUTHENTICATION_RESULTS
  -- These get logged to the APEX Login Access Log.
  --  
  --    0    Normal, successful authentication 
  --    1    Unknown User Name 
  --    2    Account Locked 
  --    3    Account Expired 
  --    4    Incorrect Password 
  --    5    Password First Use 
  --    6    Maximum Login Attempts Exceeded 
  --    7    Unknown Internal Error 
  --    8    Password complexity requirements
     p_auth_status_msg := v_auth_status_msg; 
  -- First, check to see if the user exists

    IF p_username IS NULL THEN
    v_auth_status_msg := 'Username Can''t be blank';
	apex_util.set_authentication_result(7);
	apex_util.set_custom_auth_status(v_auth_status_msg);
	dbms_output.put_line(v_auth_status_msg);
    RETURN FALSE;
    ELSIF 
        p_password IS NULL THEN
        v_auth_status_msg := 'Password Can''t be blank';
		apex_util.set_authentication_result(1);
		apex_util.set_custom_auth_status(v_auth_status_msg);
		dbms_output.put_line(v_auth_status_msg);
        RETURN FALSE;
        -- Check if the username contains '@'
    ELSIF INSTR(p_username, '@') > 0 THEN
        dbms_output.put_line('Username contains @ symbol.');
        -- Handle the case where the username contains '@'
        BEGIN 
            SELECT  UPPER(username) into v_username  FROM all_users  WHERE upper(email) = UPPER(p_username);
            dbms_output.put_line('Username from Email: '||v_username);

            SELECT COUNT(*), failed_login_attempts , first_login, account_lock_date, status
            INTO v_count, v_failed_attempts, v_first_login, v_account_lock_date, v_status
            FROM all_users 
            WHERE upper(username) = v_username --  or upper(email) = v_username
            group by failed_login_attempts, first_login, account_lock_date, status;
            dbms_output.put_line('Username From Email: '||v_username||',v_count: '||v_count||',v_failed_attempts: '||v_failed_attempts||',v_first_login: '||v_first_login||',v_account_lock_date: '||v_account_lock_date||',v_status: '||v_status);

            EXCEPTION WHEN NO_DATA_FOUND THEN
            v_auth_status_msg := 'Unknown Email Address';
			apex_util.set_authentication_result(1);
			apex_util.set_custom_auth_status(v_auth_status_msg);
			dbms_output.put_line(v_auth_status_msg);
            RETURN FALSE;
        END;
        BEGIN
            SELECT COUNT(*), failed_login_attempts , first_login, account_lock_date, status
            INTO v_count, v_failed_attempts, v_first_login, v_account_lock_date, v_status
            FROM all_users 
            WHERE upper(username) = v_username --  or upper(email) = v_username
            group by failed_login_attempts, first_login, account_lock_date, status;

            EXCEPTION WHEN NO_DATA_FOUND THEN
            v_auth_status_msg := 'Unknown Username';
			apex_util.set_authentication_result(1);
            apex_util.set_custom_auth_status(v_auth_status_msg);
			dbms_output.put_line(v_auth_status_msg);
            RETURN FALSE; 
        END;
    ELSE
    dbms_output.put_line('Username Does not contains @ symbol.');
            BEGIN
            SELECT COUNT(*), failed_login_attempts , first_login, account_lock_date, status
            INTO v_count, v_failed_attempts, v_first_login, v_account_lock_date, v_status
            FROM all_users 
            WHERE upper(username) = v_username --  or upper(email) = v_username
            group by failed_login_attempts, first_login, account_lock_date, status;
            dbms_output.put_line('Username: '||v_username||',v_count: '||v_count||',v_failed_attempts: '||v_failed_attempts||',v_first_login: '||v_first_login||',v_account_lock_date: '||v_account_lock_date||',v_status: '||v_status);

            EXCEPTION WHEN NO_DATA_FOUND THEN
            v_auth_status_msg := 'Unknown Username';
			apex_util.set_authentication_result(1);
            apex_util.set_custom_auth_status(v_auth_status_msg);
			dbms_output.put_line(v_auth_status_msg);
            RETURN FALSE; 
        END;
    END IF;

    -- L 1 (First)
    IF v_count > 0 THEN
            -- L 1.1 (First)
            IF v_status <> 1 THEN 
                v_auth_status_msg := 'Account Disabled';
                apex_util.set_authentication_result(7);
                apex_util.set_custom_auth_status(v_auth_status_msg);
				dbms_output.put_line(v_auth_status_msg);
            RETURN FALSE;

            -- L 1.2
            ELSIF
            SYSDATE > v_account_lock_date THEN
            -- Reset failed login attempts
            UPDATE all_users SET FAILED_LOGIN_ATTEMPTS = 0
            WHERE upper(username) = v_username --  or upper(email) = v_username
            ;
            -- Add Locking Time
            UPDATE all_users SET account_lock_date = NULL
            WHERE upper(username) = v_username --  or upper(email) = v_username
            ;
            commit;
                        -- Hash the provided password
                        v_hashed_password := CUSTOM_AUTHENTICATION.hash_password(v_username, p_password);
                        dbms_output.put_line('v_hashed_password: '||v_hashed_password);
                        -- Get the stored password
                        dbms_output.put_line('Before v_password: '||v_password ||'-'|| v_username);
                        SELECT PASSWORD INTO v_password
                        FROM all_users
                        WHERE upper(USERNAME) = v_username --  or upper(email) = v_username
                        ;
                        dbms_output.put_line('v_password: '||v_password);

                        -- L 1.2.1 (First) Check if the account is locked  
                        IF v_failed_attempts >= dbms_custom_authentication.max_failed_login_attempts THEN
                        -- Remaining lock time 
                        SELECT ROUND((ACCOUNT_LOCK_DATE - SYSDATE)*1440)  into v_lock_remaining_time
                        FROM all_users
                        WHERE upper(USERNAME) = v_username --  or upper(email) = v_username
                        ;
                            -- Account Locked
							v_auth_status_msg := v_failed_attempts || ' Failed attempts, Account Locked! Please try again after '|| v_lock_remaining_time || ' minutes';
                            apex_util.set_authentication_result(2);
                            apex_util.set_custom_auth_status(v_auth_status_msg);
                            dbms_output.put_line(v_auth_status_msg);
                        RETURN FALSE;

                        -- L 1.2.2 -- Check if the account is expired
                        ELSIF v_account_lock_date >= SYSDATE AND ABS(v_account_lock_date - SYSDATE)*1440 <= LOCK_TIME  THEN 
                          -- Account Expired
						  v_auth_status_msg := 'Account Locked. Please try again after '|| v_lock_remaining_time || ' minutes';
                          apex_util.set_authentication_result(3);
                          apex_util.set_custom_auth_status(v_auth_status_msg);
                          dbms_output.put_line(v_auth_status_msg);
                        RETURN FALSE;

                        -- L 1.2.3 -- Compare passwords and RETURN result
                        ELSIF v_hashed_password = v_password THEN
                                    dbms_output.put_line('successful authentication');
                                    -- Reset failed login attempts
                                    UPDATE all_users SET FAILED_LOGIN_ATTEMPTS = 0
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    -- Add Locking Time
                                    UPDATE all_users SET account_lock_date = NULL
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    commit;
									-- Normal, successful authentication
									v_auth_status_msg :=  'User:'||p_username||' is back.';
                                    apex_util.set_authentication_result(0);
                                    APEX_UTIL.SET_CUSTOM_AUTH_STATUS(v_auth_status_msg);
                                    dbms_output.put_line(v_auth_status_msg);
                                    RETURN TRUE;
                        -- L 1.2.4 (last)
                        ELSE
                        -- Increment failed login attempts
                        UPDATE all_users SET FAILED_LOGIN_ATTEMPTS = v_failed_attempts + 1
                        WHERE upper(username) = v_username --  or upper(email) = v_username
                        ;
                        commit;
                                    -- L 1.2.4.1 (First and Last)
									IF v_failed_attempts >= dbms_custom_authentication.max_failed_login_attempts-1 THEN
                                    -- Add Locking Time
                                    UPDATE all_users SET account_lock_date = SYSDATE + NUMTODSINTERVAL(LOCK_TIME, 'MINUTE')
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    commit; 
									v_auth_status_msg :=  'Password did not match.(ERR-L 1.2.4.1)';
									apex_util.set_authentication_result(4);
                                    apex_util.set_custom_auth_status(v_auth_status_msg);
									dbms_output.put_line(v_auth_status_msg);
									RETURN FALSE;
                                    END IF;	
                        -- Incorrect Password
						v_auth_status_msg :=  'Password did not match.(ERR-L 1.2.4)';     
                        apex_util.set_authentication_result(4);
                        apex_util.set_custom_auth_status(v_auth_status_msg);
						dbms_output.put_line(v_auth_status_msg);
						RETURN FALSE; 
                        END IF;
            -- L 1.3 (Last)
            ELSE
                        -- Hash the provided password
                        v_hashed_password := CUSTOM_AUTHENTICATION.hash_password(v_username, p_password);
                        dbms_output.put_line('v_hashed_password: '||v_hashed_password);
                        -- Get the stored password
                        dbms_output.put_line('Before v_password: '||v_password ||'-'|| v_username);
                        SELECT PASSWORD INTO v_password
                        FROM all_users
                        WHERE upper(USERNAME) = v_username --  or upper(email) = v_username
                        ;
                        dbms_output.put_line('v_password: '||v_password);

                        -- L 1.3.1 (First) Check if the account is locked  
                        IF v_failed_attempts >= dbms_custom_authentication.max_failed_login_attempts THEN
                        -- Remaining lock time 
                        SELECT ROUND((ACCOUNT_LOCK_DATE - SYSDATE)*1440)  into v_lock_remaining_time
                        FROM all_users
                        WHERE upper(USERNAME) = v_username --  or upper(email) = v_username
                        ;
                            -- Account Locked
                            v_auth_status_msg := v_failed_attempts || ' Failed attempts, Account Locked! Please try again after '|| v_lock_remaining_time || ' minutes';
							apex_util.set_authentication_result(2);
                            apex_util.set_custom_auth_status(v_auth_status_msg);
                            dbms_output.put_line(v_auth_status_msg);
                        RETURN FALSE;

                        -- L 1.3.2 -- Check if the account is expired
                        ELSIF v_account_lock_date >= SYSDATE AND ABS(v_account_lock_date - SYSDATE)*1440 <= LOCK_TIME  THEN 
                          -- Account Expired
                          v_auth_status_msg := 'Account Locked. Please try again after '|| v_lock_remaining_time || ' minutes';
						  apex_util.set_authentication_result(3);
                          apex_util.set_custom_auth_status(v_auth_status_msg);
						  dbms_output.put_line(v_auth_status_msg);
                        RETURN FALSE;

                        -- L 1.3.3 -- Compare passwords and RETURN result
                        ELSIF v_hashed_password = v_password THEN

                                    -- Reset failed login attempts
                                    UPDATE all_users SET FAILED_LOGIN_ATTEMPTS = 0
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    -- Add Locking Time
                                    UPDATE all_users SET account_lock_date = NULL
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    commit;
                                    dbms_output.put_line('Update faield login attempts');
									-- Normal, successful authentication
                                    v_auth_status_msg :=  'User:'||p_username||' is back.';
									apex_util.set_authentication_result(0);
									apex_util.set_custom_auth_status(v_auth_status_msg);
                                    dbms_output.put_line(v_auth_status_msg);
                                    RETURN TRUE;
                        -- L 1.3.4 (Last)
                        ELSE
                        -- Increment failed login attempts
                        UPDATE all_users SET FAILED_LOGIN_ATTEMPTS = v_failed_attempts + 1
                        WHERE upper(username) = v_username --  or upper(email) = v_username
                        ;
                        commit;
                                    -- L 1.3.4.1 (First and Last)
									IF v_failed_attempts >= dbms_custom_authentication.max_failed_login_attempts-1 THEN
                                    -- Add Locking Time
                                    UPDATE all_users SET account_lock_date = SYSDATE + NUMTODSINTERVAL(LOCK_TIME, 'MINUTE')
                                    WHERE upper(username) = v_username --  or upper(email) = v_username
                                    ;
                                    commit;
									v_auth_status_msg :=  'Password did not match.(ERR-L 1.3.4.1)';
                                    apex_util.set_authentication_result(4);
                                    apex_util.set_custom_auth_status(v_auth_status_msg);
									dbms_output.put_line(v_auth_status_msg);
									RETURN FALSE;
                                    END IF;	
                        -- Incorrect Password
                        v_auth_status_msg :=  'Password did not match.(ERR-L 1.3.4)';						
                        apex_util.set_authentication_result(4);
                        apex_util.set_custom_auth_status(v_auth_status_msg);
						dbms_output.put_line(v_auth_status_msg);

						RETURN FALSE; 
                        END IF;
            END IF;
    -- L 2 (Last)
    ELSE
            -- The username does not exist
            v_auth_status_msg :=  'Unknown User Name.'||v_username;
            apex_util.set_authentication_result(1); -- Unknown User Name
            apex_util.set_custom_auth_status(v_auth_status_msg);
			dbms_output.put_line(v_auth_status_msg);
            RETURN FALSE;
    END IF;

EXCEPTION
    WHEN OTHERS THEN
        -- Log an unknown internal error
        v_auth_status_msg :=  'Unknown Authentication-'|| sqlerrm;
        apex_util.set_authentication_result(7); -- Unknown Internal Error
        apex_util.set_custom_auth_status(v_auth_status_msg);
		dbms_output.put_line(v_auth_status_msg);
        RETURN FALSE;
END authenticate_user;
END CUSTOM_AUTHENTICATION;
/
