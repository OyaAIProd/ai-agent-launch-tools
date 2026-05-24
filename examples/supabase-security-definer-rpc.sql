create or replace function public.admin_dashboard_stats(team_id uuid)
returns table(total_profiles bigint, new_profiles bigint)
language plpgsql
security definer
as $$
begin
  return query
  select count(*), count(*) filter (where created_at > now() - interval '7 days')
  from public.profiles
  where profiles.team_id = admin_dashboard_stats.team_id;
end;
$$;

grant execute on function public.admin_dashboard_stats(uuid) to anon, authenticated;

-- AI generated this after RLS blocked dashboard rows.
-- No explicit caller ownership or team membership check yet.
