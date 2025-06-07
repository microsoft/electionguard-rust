-- Your SQL goes here
CREATE TABLE exes(
	id INTEGER NOT NULL PRIMARY KEY,
	file_name TEXT NOT NULL,
	file_path TEXT NOT NULL,
	file_modified_time TEXT NOT NULL,
	file_sha256_uchex TEXT NOT NULL,
	file_len_bytes INTEGER NOT NULL
) STRICT;

CREATE TABLE processes(
	id INTEGER NOT NULL PRIMARY KEY,
	exe_id INTEGER NOT NULL REFERENCES exes(id),
	pid INTEGER NOT NULL
) STRICT;
