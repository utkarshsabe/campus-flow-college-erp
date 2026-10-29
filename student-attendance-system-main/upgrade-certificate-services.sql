-- Student certificate services with independent HOD and Admin approval.
create table if not exists public.certificate_requests (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.profiles(id) on delete cascade,
  certificate_type text not null check (certificate_type in ('General Certificate','Bonafide Certificate','Railway Concession')),
  purpose text not null default '' check (char_length(purpose) <= 1000),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  hod_approved boolean not null default false,
  admin_approved boolean not null default false,
  rejection_reason text not null default '' check (char_length(rejection_reason) <= 1000),
  certificate_number text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists certificate_requests_student_idx on public.certificate_requests(student_id);
create index if not exists certificate_requests_status_idx on public.certificate_requests(status,created_at desc);
alter table public.certificate_requests enable row level security;
grant select,insert,update on public.certificate_requests to authenticated;

create or replace function public.guard_certificate_request()
returns trigger language plpgsql security definer set search_path=''
as $$
declare v_role text; v_institutional_role text;
begin
 select p.role::text,p.institutional_role into v_role,v_institutional_role
 from public.profiles p where p.id=(select auth.uid());
 if tg_op='INSERT' then
   if v_role <> 'student' or new.student_id <> (select auth.uid()) then
     raise exception 'Only students can submit their own certificate requests';
   end if;
   new.hod_approved := false; new.admin_approved := false;
   new.status := 'pending'; new.certificate_number := null;
 elsif tg_op='UPDATE' then
   if new.student_id <> old.student_id or new.certificate_type <> old.certificate_type or new.purpose <> old.purpose then
     raise exception 'Submitted request details cannot be changed during review';
   end if;
   if v_role='admin' then
     if new.hod_approved is distinct from old.hod_approved then raise exception 'Admin cannot change HOD approval'; end if;
   elsif v_institutional_role='hod' then
     if new.admin_approved is distinct from old.admin_approved then raise exception 'HOD cannot change Admin approval'; end if;
   else
     raise exception 'Only HOD or Admin can review certificate requests';
   end if;
   if new.hod_approved and new.admin_approved then
     new.status := 'approved';
     if old.status <> 'approved' then
       new.certificate_number := 'CERT-' || to_char(now() at time zone 'Asia/Kolkata','YYYYMMDD') || '-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,8));
     end if;
   elsif new.status <> 'rejected' then
     new.status := 'pending';
     new.certificate_number := null;
   end if;
 end if;
 new.updated_at := now();
 return new;
end $$;
drop trigger if exists certificate_request_guard on public.certificate_requests;
create trigger certificate_request_guard before insert or update on public.certificate_requests
for each row execute function public.guard_certificate_request();

drop policy if exists certificate_requests_select on public.certificate_requests;
create policy certificate_requests_select on public.certificate_requests for select to authenticated
using (student_id=(select auth.uid())
  or exists(select 1 from public.profiles p where p.id=(select auth.uid()) and (p.role='admin' or p.institutional_role='hod')));
drop policy if exists certificate_requests_insert_student on public.certificate_requests;
create policy certificate_requests_insert_student on public.certificate_requests for insert to authenticated
with check (student_id=(select auth.uid()) and exists(select 1 from public.profiles p where p.id=(select auth.uid()) and p.role='student'));
drop policy if exists certificate_requests_review on public.certificate_requests;
create policy certificate_requests_review on public.certificate_requests for update to authenticated
using (exists(select 1 from public.profiles p where p.id=(select auth.uid()) and (p.role='admin' or p.institutional_role='hod')))
with check (exists(select 1 from public.profiles p where p.id=(select auth.uid()) and (p.role='admin' or p.institutional_role='hod')));
