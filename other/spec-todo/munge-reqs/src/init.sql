// Copyright (C) Microsoft Corporation. All rights reserved.
//     MIT License
//
//    Copyright (c) Microsoft Corporation.
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE


PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

CREATE TABLE lines (
            line_n integer primary key,
            line_in_range text,
            xtext text not null );

CREATE TABLE sections (
            line_n integer primary key,
            section text not null,
            title text not null );

CREATE TABLE pages (
            line_n integer primary key,
            page_n integer );

CREATE TABLE xnotes (
            line_n integer primary key,
            section text not null,
            xtext text not null );

CREATE TABLE xreq_statuses (
            status_code text primary key,
            ordinal integer not null,
            xtext text not null );
INSERT INTO xreq_statuses VALUES('na',     1, 'Not directly applicable to implementation code');
INSERT INTO xreq_statuses VALUES('nfd',    2, 'Needs further discussion');
INSERT INTO xreq_statuses VALUES('ace',    3, 'Applicable to implementation code, but more directly covered elsewhere');
INSERT INTO xreq_statuses VALUES('nyi',    4, 'Not yet implemented');
INSERT INTO xreq_statuses VALUES('ics',   50, 'Implementation code exists covering a portion of code paths considered substantial');
INSERT INTO xreq_statuses VALUES('ute',   55, 'At least one unit test exercising a relevant code path exists');
INSERT INTO xreq_statuses VALUES('utep',  60, 'At least one unit test exercising a relevant code path is passing');
INSERT INTO xreq_statuses VALUES('uts',   65, 'Unit tests exercising a portion of code paths considered sufficient exist');
INSERT INTO xreq_statuses VALUES('utsp',  75, 'Unit tests exercising a portion of code paths considered sufficient are passing');
INSERT INTO xreq_statuses VALUES('its',   80, 'An integration test exercising a portion of code paths considered sufficient exists');
INSERT INTO xreq_statuses VALUES('itsp', 100, 'An integration test exercising a portion of code paths considered sufficient is passing');

CREATE TABLE xreqs (
            line_n integer primary key,
            section text not null,
            xtext text not null,
            status_code text,
            status_note text,
            FOREIGN KEY(status_code) REFERENCES xreq_statuses(status_code) );

CREATE TABLE xtodos (
            line_n integer primary key,
            section text not null,
            xtext text not null );

CREATE TABLE xdones (
            line_n integer primary key,
            section text not null,
            xtext text not null );

COMMIT;
