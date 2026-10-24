-- ============================================================================
--  2단계: 점검 항목 + 일일 점검 기록
--
--  - checklist_items : 모든 사람이 같이 쓰는 점검 항목 (관리자만 추가/수정/삭제)
--  - daily_checks    : 사람별 점검 기록. 각자 자기 기록만 보고 쓸 수 있고,
--                      관리자는 모든 사람의 기록을 조회할 수 있음 (RLS)
--  - 여러 번 실행해도 안전합니다.
-- ============================================================================

create table if not exists public.checklist_items (
  id         serial primary key,
  category   text not null,
  content    text not null,
  sort_order int not null default 0,
  active     boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.daily_checks (
  id         bigserial primary key,
  user_id    uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  check_date date not null,
  item_id    int not null references public.checklist_items(id) on delete cascade,
  status     text not null check (status in ('ok', 'issue', 'na')),  -- 양호 / 불량 / 해당없음
  note       text,
  updated_at timestamptz not null default now(),
  unique (user_id, check_date, item_id)
);

create index if not exists daily_checks_date_idx on public.daily_checks (check_date);

-- 테이블 접근 허용 (실제 범위는 아래 RLS 정책이 결정)
grant select, insert, update, delete on public.checklist_items to authenticated;
grant usage on sequence public.checklist_items_id_seq to authenticated;
grant select, insert, update, delete on public.daily_checks to authenticated;
grant usage on sequence public.daily_checks_id_seq to authenticated;

-- 점검 항목: 로그인한 사람은 모두 조회, 관리자만 변경
alter table public.checklist_items enable row level security;

drop policy if exists "항목 조회" on public.checklist_items;
create policy "항목 조회" on public.checklist_items
  for select to authenticated using (true);

drop policy if exists "항목 추가 (관리자)" on public.checklist_items;
create policy "항목 추가 (관리자)" on public.checklist_items
  for insert to authenticated with check (public.is_admin());

drop policy if exists "항목 수정 (관리자)" on public.checklist_items;
create policy "항목 수정 (관리자)" on public.checklist_items
  for update to authenticated using (public.is_admin());

drop policy if exists "항목 삭제 (관리자)" on public.checklist_items;
create policy "항목 삭제 (관리자)" on public.checklist_items
  for delete to authenticated using (public.is_admin());

-- 점검 기록: 본인 기록만 쓰기, 조회는 본인 + 관리자
alter table public.daily_checks enable row level security;

drop policy if exists "기록 조회 (본인/관리자)" on public.daily_checks;
create policy "기록 조회 (본인/관리자)" on public.daily_checks
  for select to authenticated using (user_id = auth.uid() or public.is_admin());

drop policy if exists "기록 추가 (본인)" on public.daily_checks;
create policy "기록 추가 (본인)" on public.daily_checks
  for insert to authenticated with check (user_id = auth.uid());

drop policy if exists "기록 수정 (본인)" on public.daily_checks;
create policy "기록 수정 (본인)" on public.daily_checks
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists "기록 삭제 (본인)" on public.daily_checks;
create policy "기록 삭제 (본인)" on public.daily_checks
  for delete to authenticated using (user_id = auth.uid());

-- 기본 점검 항목: 제조 현장 일일 안전점검 (항목이 하나도 없을 때만 추가)
insert into public.checklist_items (category, content, sort_order)
select v.category, v.content, v.sort_order
from (values
  ('작업 전 확인',      '작업자 건강상태 확인 (음주, 피로, 질병 등)',                         10),
  ('작업 전 확인',      '작업 전 안전점검회의(TBM) 실시 및 위험요인 공유',                     20),
  ('작업 전 확인',      '보호구 착용 확인 (안전모, 안전화, 보안경, 장갑, 귀마개 등)',          30),
  ('기계·설비',         '프레스·전단기 등 방호장치(광전자식, 양수조작식) 정상 작동',           40),
  ('기계·설비',         '회전체·벨트·체인·기어 등 끼임 위험부위 덮개 설치',                   50),
  ('기계·설비',         '비상정지 스위치 위치 표시 및 정상 작동',                             60),
  ('기계·설비',         '정비·청소·수리 시 전원 차단 및 잠금·표지(LOTO) 실시',                 70),
  ('운반·하역',         '지게차 작업 전 점검 (브레이크, 경광등, 후진경보기, 전조등)',          80),
  ('운반·하역',         '지게차 통로와 보행자 통로 구분 및 작업반경 출입 통제',               90),
  ('운반·하역',         '크레인·호이스트 와이어로프, 훅 해지장치, 과부하방지장치 상태',       100),
  ('운반·하역',         '컨베이어 비상정지장치 및 끼임 방지 덮개 상태',                      110),
  ('전기',              '분전반 잠금 및 누전차단기 정상 작동',                               120),
  ('전기',              '전선·이동식 전기기구 피복 손상 및 접지 상태',                       130),
  ('화재·폭발',         '소화기 비치 위치 및 압력 게이지 정상',                              140),
  ('화재·폭발',         '비상구·피난통로 확보 (적치물 없음) 및 유도등 점등',                 150),
  ('화재·폭발',         '용접·용단 등 화기작업 시 불티 비산 방지 및 화재감시자 배치',        160),
  ('화학물질·작업환경', '화학물질 MSDS 게시 및 용기 경고표지 부착',                          170),
  ('화학물질·작업환경', '인화성·유해물질 지정 장소 보관 및 누출 여부',                       180),
  ('화학물질·작업환경', '국소배기장치(후드, 덕트) 정상 가동',                                190),
  ('작업장 환경',       '작업장 바닥 정리정돈 및 미끄럼·걸림 위험 제거',                    200),
  ('작업장 환경',       '개구부·고소작업 장소 안전난간 및 덮개 설치',                       210),
  ('비상 대응',         '구급함 비치 및 비상연락망 게시',                                    220)
) as v(category, content, sort_order)
where not exists (select 1 from public.checklist_items);
