-- Migration 001: Initial graph setup for Cloud Security Fabric

-- Enable AGE extension
CREATE EXTENSION IF NOT EXISTS age;
LOAD 'age';
SET search_path = ag_catalog, "$user", public;

-- Create the graph (idempotent check)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = 'security_fabric') THEN
        PERFORM create_graph('security_fabric');
    END IF;
END
$$;

-- Create vertex labels
SELECT create_vlabel('security_fabric', 'Finding');
SELECT create_vlabel('security_fabric', 'Resource');
SELECT create_vlabel('security_fabric', 'Vulnerability');
SELECT create_vlabel('security_fabric', 'Identity');
SELECT create_vlabel('security_fabric', 'NetworkPath');
SELECT create_vlabel('security_fabric', 'Account');
SELECT create_vlabel('security_fabric', 'Repository');

-- Create edge labels
SELECT create_elabel('security_fabric', 'AFFECTS');
SELECT create_elabel('security_fabric', 'EXPLOITS');
SELECT create_elabel('security_fabric', 'HAS_ACCESS_TO');
SELECT create_elabel('security_fabric', 'ASSUMES');
SELECT create_elabel('security_fabric', 'EXPOSES');
SELECT create_elabel('security_fabric', 'BELONGS_TO');
SELECT create_elabel('security_fabric', 'CONTAINS');
SELECT create_elabel('security_fabric', 'DEPENDS_ON');
SELECT create_elabel('security_fabric', 'HAS_FINDING');
SELECT create_elabel('security_fabric', 'HOSTS');
SELECT create_elabel('security_fabric', 'REMEDIATES');

-- Metadata tracking table (relational, for watermarks and state)
CREATE TABLE IF NOT EXISTS csf_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
