-- SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
--
-- SPDX-License-Identifier: BSD-3-Clause

-- users.schema.sql
CREATE TABLE USERS (
  IP CHAR(45) PRIMARY KEY NOT NULL,
  USER CHAR(31) NOT NULL,
  ETHER CHAR(17) NOT NULL,
  ATIME INT NOT NULL,
  DESC CHAR(50)
);
