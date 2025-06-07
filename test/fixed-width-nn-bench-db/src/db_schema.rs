// @generated automatically by Diesel CLI.

diesel::table! {
    exes (id) {
        id -> Integer,
        file_name -> Text,
        file_path -> Text,
        file_modified_time -> TimestamptzSqlite,
        file_sha256_uchex -> Text,
        file_len_bytes -> BigInt,
    }
}

diesel::table! {
    processes (id) {
        id -> Integer,
        exe_id -> Integer,
        pid -> Integer,
    }
}

diesel::joinable!(processes -> exes (exe_id));

diesel::allow_tables_to_appear_in_same_query!(
    exes,
    processes,
);
