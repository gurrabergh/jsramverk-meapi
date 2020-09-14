CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) NOT NULL,
    password VARCHAR(60) NOT NULL,
    UNIQUE(email)
);

CREATE TABLE IF NOT EXISTS texts (
	id	INTEGER NOT NULL,
	heading	TEXT,
	content	TEXT,
	PRIMARY KEY(id)
);
