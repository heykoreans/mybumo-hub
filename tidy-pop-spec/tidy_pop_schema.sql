-- =====================================================================
-- TIDY POP (방 정리 퀘스트) Supabase 스키마
-- 프로젝트: tlpzztuxttsobhqprosk (game.mybumo.com 허브와 동일)
-- 실행: Supabase 대시보드 > SQL Editor 에 전체 붙여넣고 Run
--
-- 보안 구조
--  * 모든 tidy_ 테이블은 RLS ON + 정책 없음 => anon 키로 직접 읽기/쓰기 불가
--  * 앱은 오직 아래 RPC 함수(security definer)만 호출
--  * 별 잔액은 ledger(거래 기록) 합계로만 계산 => 클라이언트가 숫자를 조작할 수 없음
--  * 부모 PIN은 bcrypt 해시로 저장, 5회 틀리면 10분 잠금
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------
-- 테이블
-- ---------------------------------------------------------------------
create table if not exists public.tidy_families (
  id               uuid primary key default gen_random_uuid(),
  callsign         text not null unique,
  child_name       text not null default '',
  pin_hash         text not null,
  pin_fail_count   int  not null default 0,
  pin_locked_until timestamptz,
  created_at       timestamptz not null default now()
);

create table if not exists public.tidy_days (
  family_id      uuid not null references public.tidy_families(id) on delete cascade,
  day            date not null,
  zones          text[] not null default '{}',
  all_bonus      boolean not null default false,
  parent_checked boolean not null default false,
  streak_paid    boolean not null default false,
  primary key (family_id, day)
);

create table if not exists public.tidy_quests (
  family_id uuid not null references public.tidy_families(id) on delete cascade,
  quest_id  text not null,
  done_at   timestamptz not null default now(),
  primary key (family_id, quest_id)
);

create table if not exists public.tidy_rewards (
  id         uuid primary key default gen_random_uuid(),
  family_id  uuid not null references public.tidy_families(id) on delete cascade,
  cat        text not null check (cat in ('경험','특권','선물','용돈')),
  name       text not null check (char_length(name) between 1 and 60),
  cost       int  not null check (cost between 1 and 1000),
  active     boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.tidy_ledger (
  id         bigserial primary key,
  family_id  uuid not null references public.tidy_families(id) on delete cascade,
  delta      int  not null,
  reason     text not null,
  kind       text not null,  -- zone | all_bonus | streak | quest | parent | redeem | adjust
  created_at timestamptz not null default now()
);
create index if not exists tidy_ledger_family_idx on public.tidy_ledger(family_id, created_at desc);

alter table public.tidy_families enable row level security;
alter table public.tidy_days     enable row level security;
alter table public.tidy_quests   enable row level security;
alter table public.tidy_rewards  enable row level security;
alter table public.tidy_ledger   enable row level security;

revoke all on public.tidy_families, public.tidy_days, public.tidy_quests,
              public.tidy_rewards, public.tidy_ledger from anon, authenticated;

-- ---------------------------------------------------------------------
-- 내부 헬퍼 (anon 호출 불가)
-- ---------------------------------------------------------------------
create or replace function public._tidy_zone_ids() returns text[]
language sql immutable as $$ select array['floor','bed','desk','dresser','toys'] $$;

create or replace function public._tidy_quest_ids() returns text[]
language sql immutable as $$ select array['audition','artbox','outside','labels','photo','donate'] $$;

create or replace function public._tidy_family(p_callsign text) returns uuid
language plpgsql security definer set search_path = public as $$
declare v uuid;
begin
  select id into v from tidy_families where callsign = lower(trim(p_callsign));
  if v is null then raise exception 'family_not_found'; end if;
  return v;
end $$;

-- 클라이언트가 보낸 '오늘' 날짜는 서버 날짜 기준 ±1일만 허용 (시차 대응, 날짜 조작 방지)
create or replace function public._tidy_check_day(p_day date) returns void
language plpgsql as $$
begin
  if p_day < current_date - 1 or p_day > current_date + 1 then
    raise exception 'invalid_day';
  end if;
end $$;

-- PIN 확인: 성공 true / 실패 false (예외를 던지지 않아야 실패 횟수가 저장됨)
create or replace function public._tidy_pin_ok(p_fid uuid, p_pin text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare f tidy_families%rowtype;
begin
  select * into f from tidy_families where id = p_fid for update;
  if f.pin_locked_until is not null and f.pin_locked_until > now() then
    return false;
  end if;
  if crypt(coalesce(p_pin,''), f.pin_hash) = f.pin_hash then
    update tidy_families set pin_fail_count = 0, pin_locked_until = null where id = p_fid;
    return true;
  end if;
  -- 5번째 실패 시 10분 잠금 후 카운트 초기화
  update tidy_families
     set pin_fail_count   = case when pin_fail_count + 1 >= 5 then 0 else pin_fail_count + 1 end,
         pin_locked_until = case when pin_fail_count + 1 >= 5 then now() + interval '10 minutes' else null end
   where id = p_fid;
  return false;
end $$;

create or replace function public._tidy_streak(p_fid uuid, p_day date) returns int
language plpgsql security definer set search_path = public as $$
declare d date := p_day; c int := 0;
begin
  if not exists (select 1 from tidy_days where family_id = p_fid and day = d and cardinality(zones) = 5) then
    d := d - 1;
  end if;
  while exists (select 1 from tidy_days where family_id = p_fid and day = d and cardinality(zones) = 5) loop
    c := c + 1; d := d - 1;
  end loop;
  return c;
end $$;

create or replace function public._tidy_state(p_fid uuid, p_day date) returns json
language sql security definer set search_path = public as $$
  select json_build_object(
    'ok', true,
    'child_name', (select child_name from tidy_families where id = p_fid),
    'stars',  (select coalesce(sum(delta),0) from tidy_ledger where family_id = p_fid),
    'total',  (select coalesce(sum(delta),0) from tidy_ledger where family_id = p_fid and delta > 0 and kind <> 'adjust'),
    'streak', public._tidy_streak(p_fid, p_day),
    'days',   (select coalesce(json_agg(json_build_object('day',day,'zones',zones,'all_bonus',all_bonus,
                        'parent_checked',parent_checked,'streak_paid',streak_paid) order by day),'[]'::json)
                 from tidy_days where family_id = p_fid and day > p_day - 7 and day <= p_day),
    'quests', (select coalesce(json_agg(quest_id),'[]'::json) from tidy_quests where family_id = p_fid),
    'rewards',(select coalesce(json_agg(json_build_object('id',id,'cat',cat,'name',name,'cost',cost) order by cost),'[]'::json)
                 from tidy_rewards where family_id = p_fid and active),
    'ledger', (select coalesce(json_agg(x),'[]'::json) from (
                 select delta, reason, created_at from tidy_ledger
                  where family_id = p_fid order by id desc limit 20) x)
  )
$$;

-- ---------------------------------------------------------------------
-- 공개 RPC (anon 호출 가능)
-- ---------------------------------------------------------------------

-- 가족 만들기 (최초 1회): 기본 보상 8개 자동 생성
create or replace function public.tidy_create_family(p_callsign text, p_child_name text, p_pin text, p_today date)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v uuid; cs text := lower(trim(p_callsign));
begin
  if cs !~ '^[a-z0-9_-]{3,30}$' then return json_build_object('ok',false,'error','bad_callsign'); end if;
  if p_pin !~ '^[0-9]{4,8}$'      then return json_build_object('ok',false,'error','bad_pin_format'); end if;
  if exists (select 1 from tidy_families where callsign = cs) then
    return json_build_object('ok',false,'error','callsign_taken');
  end if;
  insert into tidy_families(callsign, child_name, pin_hash)
  values (cs, left(coalesce(p_child_name,''),20), crypt(p_pin, gen_salt('bf')))
  returning id into v;

  insert into tidy_rewards(family_id, cat, name, cost) values
    (v,'경험','아빠랑 단둘이 데이트',40),
    (v,'경험','주말 저녁 메뉴 내가 정하기',15),
    (v,'경험','친구 초대해서 놀기',50),
    (v,'특권','게임·영상 30분 더',10),
    (v,'특권','30분 늦게 자기 (주말)',20),
    (v,'선물','스티커·문구 하나',25),
    (v,'선물','갖고 싶은 책 한 권',40),
    (v,'용돈','용돈 $1 (저금통으로)',10);

  return public._tidy_state(v, p_today);
end $$;

create or replace function public.tidy_get_state(p_callsign text, p_today date)
returns json language plpgsql security definer set search_path = public as $$
begin
  perform public._tidy_check_day(p_today);
  return public._tidy_state(public._tidy_family(p_callsign), p_today);
end $$;

-- 구역 체크/해제: ±1, 5구역 완료 시 +2, 5일 연속마다 +5
create or replace function public.tidy_toggle_zone(p_callsign text, p_today date, p_zone text)
returns json language plpgsql security definer set search_path = public as $$
declare fid uuid; d tidy_days%rowtype; s int; zname text;
begin
  perform public._tidy_check_day(p_today);
  fid := public._tidy_family(p_callsign);
  if not (p_zone = any(public._tidy_zone_ids())) then
    return json_build_object('ok',false,'error','bad_zone');
  end if;
  zname := case p_zone when 'floor' then '바닥' when 'bed' then '침대' when 'desk' then '책상'
                       when 'dresser' then '서랍장 위' else '인형·장난감' end;

  insert into tidy_days(family_id, day) values (fid, p_today) on conflict do nothing;
  select * into d from tidy_days where family_id = fid and day = p_today for update;

  if p_zone = any(d.zones) then
    update tidy_days set zones = array_remove(zones, p_zone) where family_id = fid and day = p_today;
    insert into tidy_ledger(family_id, delta, reason, kind) values (fid, -1, zname||' 체크 취소', 'zone');
    if d.all_bonus then
      update tidy_days set all_bonus = false where family_id = fid and day = p_today;
      insert into tidy_ledger(family_id, delta, reason, kind) values (fid, -2, '올클리어 보너스 취소', 'all_bonus');
    end if;
  else
    update tidy_days set zones = array_append(zones, p_zone) where family_id = fid and day = p_today;
    insert into tidy_ledger(family_id, delta, reason, kind) values (fid, 1, zname||' 정리 완료', 'zone');
    if cardinality(d.zones) + 1 = 5 and not d.all_bonus then
      update tidy_days set all_bonus = true where family_id = fid and day = p_today;
      insert into tidy_ledger(family_id, delta, reason, kind) values (fid, 2, '5구역 올클리어 보너스', 'all_bonus');
      s := public._tidy_streak(fid, p_today);
      if s > 0 and s % 5 = 0 and not d.streak_paid then
        update tidy_days set streak_paid = true where family_id = fid and day = p_today;
        insert into tidy_ledger(family_id, delta, reason, kind) values (fid, 5, s||'일 연속 보너스', 'streak');
      end if;
    end if;
  end if;
  return public._tidy_state(fid, p_today);
end $$;

-- 대청소 퀘스트: 1회성 ±10
create or replace function public.tidy_toggle_quest(p_callsign text, p_today date, p_quest text)
returns json language plpgsql security definer set search_path = public as $$
declare fid uuid; qname text;
begin
  perform public._tidy_check_day(p_today);
  fid := public._tidy_family(p_callsign);
  if not (p_quest = any(public._tidy_quest_ids())) then
    return json_build_object('ok',false,'error','bad_quest');
  end if;
  qname := case p_quest when 'audition' then '인형 오디션' when 'artbox' then '작품 상자 만들기'
                        when 'outside' then '방 밖으로 보내기' when 'labels' then '라벨 붙이기'
                        when 'photo' then '완성 사진 찍기' else '나눔 상자' end;
  if exists (select 1 from tidy_quests where family_id = fid and quest_id = p_quest) then
    delete from tidy_quests where family_id = fid and quest_id = p_quest;
    insert into tidy_ledger(family_id, delta, reason, kind) values (fid, -10, qname||' 취소', 'quest');
  else
    insert into tidy_quests(family_id, quest_id) values (fid, p_quest);
    insert into tidy_ledger(family_id, delta, reason, kind) values (fid, 10, '퀘스트: '||qname, 'quest');
  end if;
  return public._tidy_state(fid, p_today);
end $$;

-- 부모님 확인 (+2, 올클리어 후 하루 1회, PIN 필요)
create or replace function public.tidy_parent_check(p_callsign text, p_today date, p_pin text)
returns json language plpgsql security definer set search_path = public as $$
declare fid uuid; d tidy_days%rowtype;
begin
  perform public._tidy_check_day(p_today);
  fid := public._tidy_family(p_callsign);
  if not public._tidy_pin_ok(fid, p_pin) then return json_build_object('ok',false,'error','bad_pin'); end if;
  select * into d from tidy_days where family_id = fid and day = p_today for update;
  if not found or not d.all_bonus then return json_build_object('ok',false,'error','not_all_done'); end if;
  if d.parent_checked then return json_build_object('ok',false,'error','already_checked'); end if;
  update tidy_days set parent_checked = true where family_id = fid and day = p_today;
  insert into tidy_ledger(family_id, delta, reason, kind) values (fid, 2, '부모님 확인 보너스', 'parent');
  return public._tidy_state(fid, p_today);
end $$;

-- 보상 교환 (PIN 필요, 잔액 부족 시 거절)
create or replace function public.tidy_redeem(p_callsign text, p_today date, p_reward uuid, p_pin text)
returns json language plpgsql security definer set search_path = public as $$
declare fid uuid; r tidy_rewards%rowtype; bal int;
begin
  perform public._tidy_check_day(p_today);
  fid := public._tidy_family(p_callsign);
  if not public._tidy_pin_ok(fid, p_pin) then return json_build_object('ok',false,'error','bad_pin'); end if;
  select * into r from tidy_rewards where id = p_reward and family_id = fid and active;
  if not found then return json_build_object('ok',false,'error','reward_not_found'); end if;
  perform 1 from tidy_families where id = fid for update;  -- 동시 교환 방지
  select coalesce(sum(delta),0) into bal from tidy_ledger where family_id = fid;
  if bal < r.cost then return json_build_object('ok',false,'error','not_enough_stars'); end if;
  insert into tidy_ledger(family_id, delta, reason, kind) values (fid, -r.cost, '교환: '||r.name, 'redeem');
  return public._tidy_state(fid, p_today);
end $$;

-- 부모 설정: 별 조정
create or replace function public.tidy_adjust(p_callsign text, p_today date, p_pin text, p_delta int, p_reason text)
returns json language plpgsql security definer set search_path = public as $$
declare fid uuid;
begin
  perform public._tidy_check_day(p_today);
  fid := public._tidy_family(p_callsign);
  if not public._tidy_pin_ok(fid, p_pin) then return json_build_object('ok',false,'error','bad_pin'); end if;
  if p_delta = 0 or abs(p_delta) > 500 then return json_build_object('ok',false,'error','bad_delta'); end if;
  insert into tidy_ledger(family_id, delta, reason, kind)
  values (fid, p_delta, coalesce(nullif(left(trim(p_reason),40),''),'부모님 조정'), 'adjust');
  return public._tidy_state(fid, p_today);
end $$;

-- 부모 설정: 보상 추가 / 삭제
create or replace function public.tidy_reward_add(p_callsign text, p_today date, p_pin text, p_cat text, p_name text, p_cost int)
returns json language plpgsql security definer set search_path = public as $$
declare fid uuid;
begin
  perform public._tidy_check_day(p_today);
  fid := public._tidy_family(p_callsign);
  if not public._tidy_pin_ok(fid, p_pin) then return json_build_object('ok',false,'error','bad_pin'); end if;
  insert into tidy_rewards(family_id, cat, name, cost) values (fid, p_cat, trim(p_name), p_cost);
  return public._tidy_state(fid, p_today);
end $$;

create or replace function public.tidy_reward_remove(p_callsign text, p_today date, p_pin text, p_reward uuid)
returns json language plpgsql security definer set search_path = public as $$
declare fid uuid;
begin
  perform public._tidy_check_day(p_today);
  fid := public._tidy_family(p_callsign);
  if not public._tidy_pin_ok(fid, p_pin) then return json_build_object('ok',false,'error','bad_pin'); end if;
  update tidy_rewards set active = false where id = p_reward and family_id = fid;
  return public._tidy_state(fid, p_today);
end $$;

-- 부모 설정: PIN 변경
create or replace function public.tidy_set_pin(p_callsign text, p_old_pin text, p_new_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare fid uuid;
begin
  fid := public._tidy_family(p_callsign);
  if not public._tidy_pin_ok(fid, p_old_pin) then return json_build_object('ok',false,'error','bad_pin'); end if;
  if p_new_pin !~ '^[0-9]{4,8}$' then return json_build_object('ok',false,'error','bad_pin_format'); end if;
  update tidy_families set pin_hash = crypt(p_new_pin, gen_salt('bf')) where id = fid;
  return json_build_object('ok',true);
end $$;

-- 부모 PIN만 확인 (설정 화면 진입용)
create or replace function public.tidy_verify_pin(p_callsign text, p_pin text)
returns json language plpgsql security definer set search_path = public as $$
begin
  return json_build_object('ok', public._tidy_pin_ok(public._tidy_family(p_callsign), p_pin));
end $$;

-- ---------------------------------------------------------------------
-- 권한: 헬퍼는 막고, 공개 RPC만 anon 에 허용
-- ---------------------------------------------------------------------
revoke execute on function public._tidy_zone_ids(), public._tidy_quest_ids(),
  public._tidy_family(text), public._tidy_check_day(date), public._tidy_pin_ok(uuid,text),
  public._tidy_streak(uuid,date), public._tidy_state(uuid,date)
  from public, anon, authenticated;

grant execute on function
  public.tidy_create_family(text,text,text,date),
  public.tidy_get_state(text,date),
  public.tidy_toggle_zone(text,date,text),
  public.tidy_toggle_quest(text,date,text),
  public.tidy_parent_check(text,date,text),
  public.tidy_redeem(text,date,uuid,text),
  public.tidy_adjust(text,date,text,int,text),
  public.tidy_reward_add(text,date,text,text,text,int),
  public.tidy_reward_remove(text,date,text,uuid),
  public.tidy_set_pin(text,text,text),
  public.tidy_verify_pin(text,text)
  to anon, authenticated;
