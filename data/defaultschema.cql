CREATE TABLE users (
	id uuid,
	username text,
	PRIMARY KEY (id)
);

CREATE TABLE users_by_username (
	username text,
	id uuid,
	PRIMARY KEY (username)
);