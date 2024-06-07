create or replace PACKAGE CUSTOM_AUTHENTICATION AS

  FUNCTION HASH_PASSWORD
    (p_username IN VARCHAR2,
     p_password IN VARCHAR2)
  RETURN VARCHAR2;
--------------------------------------------------------------------------------------------------
--FUNCTION authenticate_user Over load without out parameter--------------------------------------
--------------------------------------------------------------------------------------------------
  FUNCTION AUTHENTICATE_USER 
    (p_username IN VARCHAR2,  
     p_password IN VARCHAR2 ) 
  RETURN BOOLEAN;

--------------------------------------------------------------------------------------------------
--FUNCTION authenticate_user Over load with out parameter--------------------------------------
--------------------------------------------------------------------------------------------------
  FUNCTION authenticate_user (
    p_username IN VARCHAR2,
    p_password IN VARCHAR2,
    p_auth_status_msg OUT VARCHAR2 
) RETURN BOOLEAN;
  -- Constant for maximum failed login attempts
  MAX_FAILED_LOGIN_ATTEMPTS CONSTANT NUMBER := 10;
  LOCK_TIME CONSTANT NUMBER := 2; --minutes
END CUSTOM_AUTHENTICATION;
/
