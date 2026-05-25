-- Redacted example for self-hosted/local Supabase Security Advisor search_path review.
-- Mirrors the shape of hard-coded search paths without including project data.

create schema if not exists example_schema;

set search_path = example_schema;

create or replace function public.get_tenant_id_from_current()
returns uuid
language sql
stable
security definer
set search_path from current
as $$
  select '11111111-1111-1111-1111-111111111111'::uuid
$$;

reset search_path;

create schema if not exists example_schema_2;

create or replace function public.get_tenant_id_hardcoded()
returns uuid
language sql
stable
security definer
set search_path = 'example_schema_2'
as $$
  select '11111111-1111-1111-1111-111111111111'::uuid
$$;

-- Review evidence to collect in the real project:
-- select proname, proconfig from pg_proc where proname like 'get_tenant_id%';
