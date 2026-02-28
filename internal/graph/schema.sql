-- Cloud Security Fabric — Apache AGE Graph Schema
-- This file documents the graph schema. Actual creation is in migrations.

-- Load AGE extension
CREATE EXTENSION IF NOT EXISTS age;
LOAD 'age';
SET search_path = ag_catalog, "$user", public;

-- Create the security_fabric graph
SELECT create_graph('security_fabric');

-- Node types (labels):
--   Finding       — normalized OCSF finding
--   Resource      — cloud resource (EC2, S3, Lambda, etc.)
--   Vulnerability — CVE or vulnerability
--   Identity      — IAM user, role, service principal
--   NetworkPath   — network endpoint or path
--   Account       — cloud account
--   Repository    — code repository

-- Edge types (labels):
--   AFFECTS           — Finding → Resource
--   EXPLOITS          — Finding → Vulnerability
--   HAS_ACCESS_TO     — Identity → Resource
--   ASSUMES           — Identity → Identity (role assumption)
--   EXPOSES           — Resource → NetworkPath
--   BELONGS_TO        — Resource → Account
--   CONTAINS          — Resource → Resource (parent-child)
--   DEPENDS_ON        — Resource → Resource (dependency)
--   HAS_FINDING       — Resource → Finding
--   HOSTS             — Resource → Repository
--   REMEDIATES        — Finding → Finding (fix relationship)
