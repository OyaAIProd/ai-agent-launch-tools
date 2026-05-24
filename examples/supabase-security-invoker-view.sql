create or replace view public.exposed_api as
select id, email, team_id, role
from public.profiles;

grant select on public.exposed_api to anon, authenticated;

-- Dashboard copied definition lost WITH (security_invoker = true).
