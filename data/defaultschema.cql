// Users, keyed by user id
CREATE TABLE users (
    userid uuid,
    username text,
    password_hash text,
    security_stamp text,
    two_factor_enabled boolean,
    access_failed_count int,
    lockout_enabled boolean,
    lockout_end_date timestamp,
    phone_number text,
    phone_number_confirmed boolean,
    email text,
    email_confirmed boolean,
    PRIMARY KEY (userid)
);

// Users, keyed by username
CREATE TABLE users_by_username (
    username text,
    userid uuid,
    password_hash text,
    security_stamp text,
    two_factor_enabled boolean,
    access_failed_count int,
    lockout_enabled boolean,
    lockout_end_date timestamp,
    phone_number text,
    phone_number_confirmed boolean,
    email text,
    email_confirmed boolean,
    PRIMARY KEY (username)
);

// Users, keyed by email address
CREATE TABLE users_by_email (
    email text,
    userid uuid,
    username text,
    password_hash text,
    security_stamp text,
    two_factor_enabled boolean,
    access_failed_count int,
    lockout_enabled boolean,
    lockout_end_date timestamp,
    phone_number text,
    phone_number_confirmed boolean,
    email_confirmed boolean,
    PRIMARY KEY (email)
);

// Logins, keyed by user id
CREATE TABLE logins (
    userid uuid,
    login_provider text,
    provider_key text,
    PRIMARY KEY(userid, login_provider, provider_key)
);

// Logins, keyed by provider and provider key
CREATE TABLE logins_by_provider (
    login_provider text,
    provider_key text,
    userid uuid,
    PRIMARY KEY ((login_provider, provider_key))
);

// Claims, keyed by user id
CREATE TABLE claims (
    userid uuid,
    type text,
    value text,
    PRIMARY KEY (userid, type, value)
);