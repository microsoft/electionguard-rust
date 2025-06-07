--
--
--

-- @block create spec_ver table -------------------------------------------------------------------|
drop table if exists spec_ver;
create table if not exists spec_ver(
    ver int primary key,
    vnnn text,
    spec_date text
) strict;
insert into spec_ver values
  ( 200, 'v2.0.0', 'August 18, 2023'
),( 210, 'v2.1.0', 'August 12, 2024'
);

-- @block
-- @label select
-- @name query all spec_ver
select * from spec_ver;

-- @block recreate table v200_sec_titles ----------------------------------------------------------|
-- @label do mapping

-- @label drop
drop table if exists v200_sec_titles;

-- @label create
create table if not exists v200_sec_titles(
    v200_sec, v200_sec_title
);
insert into v200_sec_titles(
    v200_sec, v200_sec_title
) values
--       sec  sec_title
  (  '3.2.2', 'Details of key generation'
--),(   NULL, ''
)

-- @block see all v200_sec_titles
select * from v200_sec_titles;

-- @block recreate table v210_sec_titles ----------------------------------------------------------|

-- @label drop
drop table if exists v210_sec_titles;

-- @label create
create table if not exists v210_sec_titles(
    v210_sec, v210_sec_title
);
-- v210
insert into v210_sec_titles(
    v210_sec, v210_sec_title
) values
--       sec  sec_title
  (      '3',  'Components'
),(  '3.1.1',  'Standard Baseline Cryptographic Parameters'
),(  '3.1.2',  'Parameter Base Hash'
),(  '3.1.3',  'Election Parameters and the Election Manifest'
),(  '3.1.4',  'Election Base Hash'
),(  '3.2.1',  'Overview of key generation'
),(  '3.2.2',  'Details of key generation'
),(  '3.3.1',  'Selection Encryption'
),(  '3.3.2',  'Selection Encryption Identifiers and Identifier Hash'
),(  '3.3.3',  'Generation of the Ballot Nonce and Encryption Nonces'
),(  '3.3.4',  'Encryption of Ballot Nonces'
),(  '3.3.7',  'Details for Proofs of Ballot Correctness'
),(  '3.3.8',  'Proof of Satisfying the Contest Selection Limit'
),(  '3.3.10',  'Contest Data'
),(  '3.4',    'Confirmation Codes'
),(  '3.4.1',  'Contest Hash'
),(  '3.4.2',  'Confirmation Code'
),(  '3.4.3',  'Voting Device Information Hash'
),(  '3.4.4a', 'Ballot Chaining - No chaining'
),(  '3.4.4b', 'Ballot Chaining - Simple chaining'
),(  '3.5',    'Ballot Aggregation'
),(  '3.6.2',  'Verifiable Decryption Strategy'
),(  '3.6.3',  'Partial Decryption by Available Guardians'
),(  '3.6.4',  'Combination of Partial Decryptions'
),(  '3.6.5',  'Proof of Correctness'
),(  '3.6.6',  'Decryption of Contest Data (Optional)'
),(  '3.6.7',  'Decryption of Challenged Ballots'
),(  '4.1',    'Format of Pre-Encrypted Ballots'
),(  '4.1.1',  'Selection Hash'
),(  '4.1.2',  'Contest Hash'
),(  '4.1.3',  'Confirmation Code'
),(  '4.1.4',  'Ballot Chaining'
),(  '4.2.1',  'Deterministic Nonce Derivation'
),(  '5',      'Hash Computation'
),(  '5.1',    'Input Data Representation'
),(  '5.1.1',  'Integers Modulo the Large Prime p'
),(  '5.1.2',  'Integers Modulo the Small Prime q'
),(  '5.2',    'Hash Function'
),(  '5.4',    'Hash Function Outputst and Hashing to Z_q'
)

-- @block see all v210_sec_titles
select * from v210_sec_titles;

-- @block recreate table mapping ------------------------------------------------------------------|

-- @label drop if exists mapping
drop table if exists mapping;

-- @label create
create table if not exists mapping(
    v200_pg, v200_sec, v200_eq, v200_var,
    v210_pg, v210_sec, v210_eq, v210_var, v210_var_description
);

-- @label insert v200, v210 items with mappings
insert into mapping(
    v200_pg, v200_sec, v200_eq, v200_var,
    v210_pg, v210_sec, v210_eq, v210_var, v210_var_description
) values
-- |----- v200 ----------------------|   |---- v210 ------------------------------------------------------|
--   pg       sec      eq    var           pg        sec            eq    var                    v210_var_description
  (   22,  '3.2.2',     11, NULL,          23,   '3.2.2',           10,   'h_{i,j}',                  NULL
),(   22,  '3.2.2',     12, NULL,          23,   '3.2.2',           11,   'c_i',                      NULL
),(   23,  '3.2.2',     14, NULL,          25,   '3.2.2',           15,   '(α_{i,l},β_{i,l})',        'share_encrypt_ct'
),(   23,  '3.2.2',     15, NULL,          25,   '3.2.2',           16,   'k_{i,l}',                  'hash_shareenc'
),(   23,  '3.2.2',     16, NULL,          25,   '3.2.2',           17,   'k_{i,l,1}',                'share_enc_ENCkey'
),(   23,  '3.2.2',     17, NULL,          25,   '3.2.2',           18,   'k_{i,l,2}',                'share_enc_ENCkey2'
),(   24,  '3.2.2',     18, NULL,          25,   '3.2.2',           19,   'E_l(P_i(l),Phat_i(l))',    'E_\ell(P_i(\ell), \hat{P}_i(\ell))'
),(   24,  '3.2.2',     19, NULL,          25,   '3.2.2',           20,   'C_{i,l,0}',                'C_{i,\ell,0}'
),(   24,  '3.2.2',     19, NULL,          25,   '3.2.2',           21,   'C_{i,l,1}',                'C_{i,\ell,1}'
),(   24,  '3.2.2',     19, NULL,          25,   '3.2.2',           22,   'cbar_{i,l}',               '\bar c_{i,\ell}'
),(   24,  '3.2.2',     19, NULL,          25,   '3.2.2',           22,   'vbar_{i,l}',               '\bar v_{i,\ell}'
),(   25,  '3.2.3',     23, NULL,          28,   '3.3.1',           30,   'H_E',                      'extended base hash'
),(   26,  '3.3.2',     25, 'ξ_B',         29,   '3.3.3',           33,   'ξ_B',                      'ballot nonce'
),(   26,  '3.3.2',     25, 'ξ_{i,j}',     29,   '3.3.3',           33,   'ξ_{i,j}',                  'contest i option j nonce'
),(   35,  '3.4.2',     58, NULL,          42,   '3.4.2',           71,   'H_C',                      'ballot confirmation code'
),(   39,  '3.6.3',     69, NULL,          47,   '3.6.5',           87,    '(a_i,b_i)',               'NIZK proof of M'
),(   39,  '3.6.3',     70, NULL,          48,   '3.6.5',           89,   'a',                        'NIZK proof of M'
),(   39,  '3.6.3',     71, NULL,          48,   '3.6.5',           90,   'c',                        'NIZK proof of M'
),(   39,  '3.6.3',     72, NULL,          48,   '3.6.5',           91,   'c_i',                      'NIZK proof of M'
),(   40,  '3.6.3',     73, NULL,          48,   '3.6.5',           92,   'v_i',                      'NIZK proof of M'
),(   40,  '3.6.3',     74, NULL,          48,   '3.6.5',           94,   'a''_i',                    'NIZK proof of M'
),(   40,  '3.6.3',     75, NULL,          48,   '3.6.5',           95,   'b''_i',                    'NIZK proof of M'
);

-- v210 items without mappings
insert into mapping(
    v210_sec, v210_pg, v210_eq, v210_var, v210_var_description
) values
-- |---- v210 --------------------------------------------|
--       sec  pg   eq   var                         description
  (      '3', 10,   1,  NULL,                       NULL
),(      '3', 11,   2,  NULL,                       NULL
),(  '3.1.1', 14,   3,  'q',                        NULL
),(  '3.1.2', 16,   4,  'H_P',                      NULL
),(  '3.1.4', 19,   5,  'H_B',                      NULL
),(  '3.2.1', 21,   6,  's_i',                      NULL
),(  '3.2.1', 21,   6,  'a_{i,j}',                  NULL
),(  '3.2.1', 21,   6,  'K',                        NULL
),(  '3.2.1', 21,   6,  'K_{i,j}',                  NULL
),(  '3.2.1', 22,   6,  'P_i(x)',                   NULL
),(  '3.2.1', 22,   6,  'P(x)',                     NULL
),(  '3.2.2', 22,   7,  's_i = a_{i,0}',            'secret key for guardian G_i'
),(  '3.2.2', 22,   7,  'a_{i,0<j}',                NULL
),(  '3.2.2', 22,   7,  'K_i = K_{i,0}',            NULL
),(  '3.2.2', 22,   7,  'P_i(x)',                   NULL
),(  '3.2.2', 22,   8,  'K_{i,j}',                  NULL
),(  '3.2.2', 23,   8,  'ahat_{i,0}',               'secret key for guardian G_i'
),(  '3.2.2', 23,   8,  'ahat_{i,0<j}',             NULL
),(  '3.2.2', 23,   8,  'K_i = K_{i,0}',            'public key for guardian G_i'
),(  '3.2.2', 23,   8,  'Phat_i(x)',                NULL
),(  '3.2.2', 23,   8,  'Khat_{i,j}',               NULL
),(  '3.2.2', 23,   9,  'zeta_i',                   NULL
),(  '3.2.2', 23,   9,  'κ_i',                      NULL
),(  '3.2.2', 24,  12,  '\hat{h}_{i,j}',            NULL
),(  '3.2.2', 24,  13,  '\hat{c}_{i}',              NULL
),(  '3.2.2', 24,  14,  'g^{P_i(\alpha)}',          NULL
),(  '3.2.2', 26,  23,  '\bytes(P_i(\ell),32)\parallel \bytes(\hat{P}_i(\ell),32)',      NULL
),(  '3.2.2', 26,  24,  'z_i',                      'guardian $G_i$''s share of the of the vote encryption secret key'
),(  '3.2.2', 26,  24,  '\hat{z}_i',                'guardian $G_i$''s share of the ballot data encryption secret key'
),(  '3.2.2', 26,  25,  'K',                        'joint vote encryption public key'
),(  '3.2.2', 26,  26,  '\hat{K}',                  'joint ballot data encryption public key'
),(  '3.2.2', 27,  27,  '\HH_{G}',                  'hash of all the key data'
),(  '3.2.2', 27,  28,  'g^{P_i(\ell)}',            'verification check for the ${P}_i(\ell)$ and the ${K}_{i,j}$'
),(  '3.2.2', 27,  29,  'g^{\hat P_i(\ell)}',       'verification check for the $\hat{P}_i(\ell)$ and the $\hat{K}_{i,j}$'
),(  '3.3.1', 28,  31,  '(\alpha, \beta)',          'encryption of ballot contest option selection'
),(  '3.3.2', 29,  32,  'id_B',                     'selection encryption identifier'
),(  '3.3.2', 29,  32,  '\HH_I',                    'selection encryption identifier hash'
),(  '3.3.4', 30,  34,  '\hat{\xi}_B',              'ballot nonce encryption nonce'
),(  '3.3.4', 30,  34,  '(\alpha_B, \beta_B)',      'encryption of ballot nonce'
),(  '3.3.4', 30,  35,  'h',                        'master-key-enc-of-ballot-nonce, 256-bit secret key'
),(  '3.3.4', 30,  36,  'k_1',                      'encryption key $k_1$, derived-keys-enc-of-ballot-nonce'
),(  '3.3.4', 30,  37,  'C_{\xi_B}',                'encryption of ballot nonce'
),(  '3.3.4', 30,  37,  'C_{\xi_B,0}',              'encryption of ballot nonce 1 of 3'
),(  '3.3.4', 30,  37,  'C_{\xi_B,1}',              'encryption of ballot nonce 2 of 3'
),(  '3.3.4', 30,  38,  'u_B',                      'eq. 38 uniform random integer'
),(  '3.3.4', 30,  38,  'a_B',                      'eq. 38 committment'
),(  '3.3.4', 30,  38,  'c_B',                      'eq. 38 challenge'
),(  '3.3.4', 30,  38,  'v_B',                      'eq. 38 response value'
),(  '3.3.4', 30,  38,  'C_{\xi_B,2}',              'Schnorr proof of knowledge for $\hat{\xi}_B$'
),(  '3.3.7', 34,  39,  'u_0',                      'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  39,  'u_1',                      'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  39,  'c_1',                      'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  39,  '(a_0, b_0)',               'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  40,  '(a_1, b_1)',               'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  41,  'c',                        'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  42,  'c_0',                      'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  43,  'v_0',                      'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  44,  'v_1',                      'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  45,  'c',                        'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  46,  '(g^{v_0} \alpha^{c_0}, K^{v_0} \beta^{c_0})',               'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  47,  '(g^{v_1} \alpha^{c_1}, K^{v_1-c_1} \beta^{c_1})',           'Unselected option NIZK proof that contest option selection is zero or one'
),(  '3.3.7', 34,  48,  '(a_0, b_0)',               'Selected option NIZK proof of zero or one'
),(  '3.3.7', 35,  49,  '(a_1, b_1)',               'Selected option NIZK proof of zero or one'
),(  '3.3.7', 35,  50,  'c',                        'Selected option NIZK proof of zero or one'
),(  '3.3.7', 35,  51,  'c_0',                      'Selected option NIZK proof of zero or one'
),(  '3.3.7', 35,  52,  'v_0',                      'Selected option NIZK proof of zero or one'
),(  '3.3.7', 35,  53,  'v_1',                      'Selected option NIZK proof of zero or one'
),(  '3.3.7', 35,  54,  'c',                        'Selected option NIZK proof of zero or one'
),(  '3.3.7', 35,  55,  '(g^{v_0} \alpha^{c_0}, K^{v_0} \beta^{c_0})',             'Selected option NIZK proof of zero or one'
),(  '3.3.7', 35,  56,  '(g^{v_1} \alpha^{c_1}, K^{v_1-c_1} \beta^{c_1})',         'Selected option NIZK proof of zero or one'
),(  '3.3.7', 35,  57,  'u_j, 0<=j<=R',             'General case NIZK range proof'
),(  '3.3.7', 35,  57,  '(a_\ell,b_\ell)',          'General case NIZK range proof'
),(  '3.3.7', 35,  58,  'c_j, 0<=j<=R',             'General case NIZK range proof'
),(  '3.3.7', 35,  58,  't_j',                      'General case NIZK range proof'
),(  '3.3.7', 35,  58,  '(a_j,b_j)',                'General case NIZK range proof'
),(  '3.3.7', 35,  59,  'c',                        'General case NIZK range proof'
),(  '3.3.7', 35,  60,  'c_\ell',                   'General case NIZK range proof'
),(  '3.3.7', 36,  61,  'v_j',                      'General case NIZK range proof'
),(  '3.3.8', 37,  62,  '(\bar\alpha,\bar\beta)',   'aggregate contest encryption'
),(  '3.3.8', 37,  62,  '\xi',                      'aggregate nonce'
),(  '3.3.8', 37,  62,  'c',                        'Contest selection limit NIZK proof'
),( '3.3.10', 40,  63,  'D_\Lambda',                'contest data field as a concatenation of blocks '
),( '3.3.10', 40,  64,  '\xi',                      'pseudo-random nonce'
),( '3.3.10', 40,  65,  'h',                        'secret key'
),( '3.3.10', 40,  66,  'k_i',                      'encryption keys k_1 .. '
),( '3.3.10', 41,  67,  'C_0',                      'ciphertext encrypting $D_\Lambda$'
),( '3.3.10', 41,  68,  'C_1',                      'ciphertext encrypting $D_\Lambda$'
),( '3.3.10', 41,  69,  'c',                        'proof of knowledge of the nonce ξ'
),(  '3.4.1', 41,  70,  'χ_l',                      'contest hash value'
),(  '3.4.3', 42,  72,  'H_DI',                     'device information hash'
),( '3.4.4a', 42,  73,  'B_C',                      'No chaining, chaining field'
),( '3.4.4b', 43,  74,  'H_0',                      'Simple chaining, chaining field'
),( '3.4.4b', 43,  75,  'B_C,0',                    'Simple chaining, hash input'
),( '3.4.4b', 43,  76,  'B_C,j',                    'Simple chaining, chaining field'
),( '3.4.4b', 43,  77,  '\overline{\HH}',           'Simple chaining, closing value'
),( '3.4.4b', 43,  78,  '\overline\B_{C}',          'Simple chaining, hash input'
),(    '3.5', 44,  79,  '(A, B)',                   'published contest option encrypted tally'
),(    '3.5', 45,  80,  '(A, B)',                   'published contest option encrypted tally (weighted)'
),(  '3.6.2', 46,  81,  'M',                        'verifiable decryption intermediate value'
),(  '3.6.2', 46,  82,  'T',                        'verifiable decryption intermediate value'
),(  '3.6.2', 46,  82,  't',                        'contest option tally'
),(  '3.6.3', 46,  83,  'z_i',                      '$G_i$''s share of the implicit secret key $s'
),(  '3.6.3', 46,  84,  'M_i',                      'partial decryption for available guardian $G_i$'
),(  '3.6.4', 47,  85,  'w_i',                      'Lagrange coefficients correspoinding to available guardians'
),(  '3.6.4', 47,  86,  'M',                        NULL
),(  '3.6.5', 47,  88,  'd_i',                      'NIZK proof of M'
),(  '3.6.5', 48,  93,  'v',                        'NIZK proof of M'
),(  '3.6.6', 50,  96,  'm_i',                      'Contest data, partial decryption for guardian $G_i$'
),(  '3.6.6', 50,  97,  'β',                        'Contest data, combined partial decryptions'
),(  '3.6.6', 50,  98,  '(a_i, b_i)',               'Contest data, partial decryption, NIZK proof'
),(  '3.6.6', 50,  99,  'd_i',                      'Contest data, partial decryption, NIZK proof'
),(  '3.6.6', 50, 100,  'a, b',                     'Contest data, partial decryption, NIZK proof'
),(  '3.6.6', 50, 101,  'c',                        'Contest data, partial decryption, NIZK proof'
),(  '3.6.6', 50, 102,  'v_i',                      'Contest data, partial decryption, NIZK proof'
),(  '3.6.6', 50, 103,  'v',                        'Contest data, partial decryption, NIZK proof'
),(  '3.6.6', 51, 104,  'k_i',                      'decryption key'
),(  '3.6.6', 51, 105,  'C_1',                      'data blocks'
),(  '3.6.6', 51, 106,  'D',                        'byte array with overvote, undervote, null vote data, and write-in text fields'
),(  '3.6.7', 52, 107,  'm_i',                      'Partial decryption of ballot nonces'
),(  '3.6.7', 52, 108,  'β_B',                      'Partial decryption of ballot nonces'
),(  '3.6.7', 52, 109,  'K^σ',                      'Decryption with encryption nonces'
),(  '3.6.7', 52, 110,  'β',                        'Decryption with encryption nonces'
),(  '3.6.7', 52, 111,  'D',                        'Decryption with encryption nonces'
),(    '4.1', 57, 112,  'Ψ_{i,m}',                  'Pre-encrypted ballot, contest option vector'
),(  '4.1.1', 58, 113,  'ψ_i',                      'Pre-encrypted ballot, contest selection hash'
),(  '4.1.1', 58, 114,  'ψ_{m + l}',                'Pre-encrypted ballot, contest selection hash'
),(  '4.1.2', 58, 115,  'χ_l',                      'Pre-encrypted ballot, contest hash'
),(  '4.1.3', 58, 116,  'H_C',                      'Pre-encrypted ballot, confirmation code'
),(  '4.1.4', 59, 117,  'H_0',                      'Pre-encrypted ballot, chaining field'
),(  '4.1.4', 59, 118,  '\overline{\HH}',           'Pre-encrypted ballot, closing value'
),(  '4.1.4', 59, 119,  '\HH_{DI}',                 'Pre-encrypted ballot, device information hash'
),(  '4.1.4', 59, 120,  '\overline\B_{C}',          'Pre-encrypted ballot, hash input'
),(  '4.2.1', 61, 121,  'ξ_{i,j,k}',                'nonce for context i option j'
),(    '5.1', 69, 122,  'a',                        'definition of big endian'
),(    '5.1', 69, 123,  'b(a, m)',                  'definition of big endian'
),(  '5.1.1', 70, 124,  'b(a, l_p)',                'definition of big endian'
),(  '5.1.1', 70, 125,  'b_i',                      'definition of big endian'
),(  '5.1.1', 70, 126,  'a',                        'definition of big endian'
),(  '5.1.2', 70, 127,  'b(a, 32)',                 'definition of big endian'
),(  '5.1.2', 70, 128,  'b_i',                      'definition of big endian'
),(  '5.1.2', 70, 129,  'a',                        'definition of big endian'
),(    '5.2', 70, 130,  'H',                        'HMAC-SHA-256'
),(    '5.4', 70, 131,  'a',                        'definition of big endian'
),(    '5.2', 70, 132,  'H_q',                      'HMAC-SHA-256 modulo small prime q'
);

-- @block Select all from mapping
select * from mapping;

-- @block mapping add v210_sec_title -------------------------------------------|

--alter table mapping drop column v210_sec_title;
--alter table mapping drop column m_v210_sec_title;

alter table mapping add column m_v210_sec_title;

update mapping as m
set m_v210_sec_title = t.v210_sec_title
from v210_sec_titles as t
where m.v210_sec = t.v210_sec
  and m_v210_sec_title is null
  and t.v210_sec_title is not null;

alter table mapping rename column m_v210_sec_title to v210_sec_title;

-- @block
select distinct
  m.v210_sec as m_v210_sec,
  t.v210_sec as t_v210_sec,
  m.v210_sec_title as m_v210_sec_title,
  t.v210_sec_title as t_v210_sec_title
from mapping as m
inner join v210_sec_titles as t on (m.v210_sec = t.v210_sec)
where true
  --and m_v210_sec_title is null
  --and t_v210_sec_title is not null
;

-- @block Bookmarked query
-- @group Ungrouped
-- @name 210 equations
select v210_pg, v210_sec, v210_sec_title, v210_eq, v210_var, v210_var_description
from mapping
where v210_pg is not null or v210_sec is not null or v210_eq is not null or v210_var is not null or v210_var_description is not null
order by v210_eq, v210_pg
;
-- @block union v200 and v210 columns -------------------------------------------|
select
200 as eg_spec_v,
rowid as common_eq_id, -- if v200_eq is not null
v200_pg as pg,
v200_eq as eq,
v200_sec as sec,
NULL as sec_title
from mapping
union all
select
210 as eg_spec_v,
rowid as common_eq_id,
v210_pg as pg,
v210_eq as eq,
v210_sec as sec,
v210_sec_title as sec_title
from mapping
;

-- @block union v200 and v210 columns
select
200 as eg_spec_v,
rowid as common_eq_id, -- if v200_eq is not null
v200_pg as pg,
v200_eq as eq,
v200_sec as sec,
NULL as sec_title
from mapping
union all
select
210 as eg_spec_v,
rowid as common_eq_id,
v210_pg as pg,
v210_eq as eq,
v210_sec as sec,
v210_sec_title as sec_title
from mapping
;

-- @block
select
210 as eg_spec_v,
min(v210_pg) as pg_min, max(v210_pg) as pg_max,
min(v210_eq) as eq_min, max(v210_eq) as eq_max,
v210_sec as sec_nnn, v210_sec_title as sec_title
from mapping
group by v210_sec
;

