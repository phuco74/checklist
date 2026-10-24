-- ============================================================================
--  중대재해 안전점검 시스템 - Supabase 초기 설정 (테이블 + 사용자 3명 + 관리자)
--
--  사용법
--  1. 아래 "사용자 목록" 부분의 아이디 / 비밀번호 / 이름을 원하는 값으로 바꾸기
--  2. Supabase > SQL Editor > New query 에 이 파일 전체를 붙여넣고 Run
--
--  - 여러 번 실행해도 안전합니다. (이미 있는 테이블/사용자는 건너뜀)
--  - 로그인 화면에서는 아이디만 입력합니다. (내부적으로 아이디@safety.local 사용)
--  - 비밀번호는 6자 이상이어야 합니다.
-- ============================================================================


-- ---------------------------------------------------------------------------
-- 1. 사용자 프로필 테이블 (아이디, 이름, 권한)
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
  id           uuid primary key references auth.users(id) on delete cascade,
  username     text unique not null,
  display_name text,
  role         text not null default 'user' check (role in ('admin', 'user')),
  created_at   timestamptz not null default now()
);

-- 관리자 여부 확인 함수 (RLS 정책에서 사용)
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.profiles where id = auth.uid() and role = 'admin'
  );
$$;

-- 새 사용자가 생기면 프로필 자동 생성
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, username, display_name)
  values (
    new.id,
    split_part(new.email, '@', 1),
    coalesce(new.raw_user_meta_data ->> 'display_name', split_part(new.email, '@', 1))
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 권한: 본인 프로필만 조회, 관리자는 전체 조회/수정
-- (로그인한 사용자에게 테이블 접근 허용 → 실제로 볼 수 있는 행은 아래 RLS 정책이 결정)
grant select, update on public.profiles to authenticated;
alter table public.profiles enable row level security;

drop policy if exists "본인 또는 관리자 조회" on public.profiles;
create policy "본인 또는 관리자 조회" on public.profiles
  for select using (id = auth.uid() or public.is_admin());

drop policy if exists "관리자만 수정" on public.profiles;
create policy "관리자만 수정" on public.profiles
  for update using (public.is_admin());


-- ---------------------------------------------------------------------------
-- 2. 사용자 3명 생성 + 관리자 지정
-- ---------------------------------------------------------------------------
do $$
declare
  -- ===== 사용자 목록: 여기만 수정하세요 =====
  --        아이디       비밀번호            이름        권한
  users text[][] := array[
    array['admin',  'change-me-admin', '관리자',   'admin'],
    array['user1',  'change-me-user1', '기록자1',  'user'],
    array['user2',  'change-me-user2', '기록자2',  'user']
  ];
  -- =========================================
  u        text[];
  v_email  text;
  v_id     uuid;
begin
  foreach u slice 1 in array users loop
    v_email := lower(u[1]) || '@safety.local';

    select id into v_id from auth.users where email = v_email;

    if v_id is null then
      v_id := gen_random_uuid();

      insert into auth.users (
        instance_id, id, aud, role, email, encrypted_password,
        email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
        created_at, updated_at,
        confirmation_token, recovery_token, email_change,
        email_change_token_new, email_change_token_current,
        phone_change, phone_change_token, reauthentication_token
      ) values (
        '00000000-0000-0000-0000-000000000000', v_id, 'authenticated', 'authenticated',
        v_email, extensions.crypt(u[2], extensions.gen_salt('bf')),
        now(), '{"provider":"email","providers":["email"]}',
        jsonb_build_object('display_name', u[3]),
        now(), now(),
        '', '', '', '', '', '', '', ''
      );

      insert into auth.identities (
        id, user_id, provider_id, provider, identity_data,
        last_sign_in_at, created_at, updated_at
      ) values (
        gen_random_uuid(), v_id, v_id::text, 'email',
        jsonb_build_object('sub', v_id::text, 'email', v_email, 'email_verified', true),
        now(), now(), now()
      );

      raise notice '생성: % (%)', u[1], u[3];
    else
      raise notice '이미 있음, 건너뜀: %', u[1];
    end if;

    -- 이름과 권한은 매번 목록 기준으로 맞춤
    update public.profiles
       set display_name = u[3],
           role         = u[4]
     where id = v_id;
  end loop;
end;
$$;


-- ---------------------------------------------------------------------------
-- 3. 결과 확인 (Run 후 아래에 3명이 보이면 성공)
-- ---------------------------------------------------------------------------
select username as 아이디, display_name as 이름, role as 권한
from public.profiles
order by role, username;
