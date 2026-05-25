-- Redacted example for unexpected default EXECUTE exposure on Supabase RPCs.
-- Mirrors a review packet shape: no secrets, no project ref, no real table data.

drop schema if exists api_test cascade;
create schema api_test;
grant usage on schema api_test to anon, authenticated;

alter default privileges in schema api_test
  revoke execute on functions from public, anon, authenticated, service_role;

create function api_test.return_null()
returns text
language plpgsql
as $$
begin
  return null;
end;
$$;

-- Redacted pg_proc / ACL note copied from a local review:
-- proacl = {=X/postgres,postgres=X/postgres,service_role=X/postgres}

-- Redacted REST smoke note:
-- POST /rest/v1/rpc/return_null as anon returned 200 success, even though no explicit grant was applied.

-- Launch expectation:
-- Add a function-specific REVOKE EXECUTE after creation, then keep anon and authenticated deny tests.
