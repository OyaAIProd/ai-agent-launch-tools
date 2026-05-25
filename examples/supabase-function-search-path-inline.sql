-- Redacted example for Supabase Security Advisor Function Search Path Mutable tradeoff.
-- The function is intentionally simplified and contains no project secrets.

create schema if not exists internal;

create table internal.item (
  prop uuid not null,
  id text not null,
  data jsonb not null,
  label_tsv tsvector generated always as (to_tsvector('english', data -> 'label')) stored,
  primary key (prop, id)
);

create index item_label_idx on internal.item using gin (label_tsv);

create or replace function public.fetch_by_prop(prop_value uuid)
returns setof internal.item
language sql
stable
set search_path = ''
as $$
  select i.*
  from internal.item i
  where i.prop = prop_value
$$;

-- Caller query to inspect with EXPLAIN before and after search_path remediation:
select *
from public.fetch_by_prop('00000000-0000-0000-0000-000000000000')
where label_tsv @@ to_tsquery('english', 'launch');
