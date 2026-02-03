# backend/app/schema.py
from .db import get_conn

SCHEMA_SQL = """
-- ----------------------------
-- Auth / Users
-- ----------------------------
create table if not exists users (
  id bigserial primary key,
  username text unique not null,
  display_name text not null,
  role text not null check (role in ('standard','admin')),
  is_active boolean not null default true,
  totp_secret_enc text,
  created_at timestamptz not null default now()
);

create table if not exists enrol_tokens (
  id bigserial primary key,
  user_id bigint not null references users(id) on delete cascade,
  token_hash text unique not null,
  totp_secret_enc text not null,
  expires_at timestamptz not null,
  used_at timestamptz
);

create table if not exists audit_log (
  id bigserial primary key,
  actor_user_id bigint references users(id) on delete set null,
  action text not null,
  target text,
  ip text,
  created_at timestamptz not null default now()
);

-- ----------------------------
-- Reference data
-- ----------------------------
create table if not exists crew_members (
  id bigserial primary key,
  name text not null unique,
  is_active boolean not null default true
);

create table if not exists appliances (
  id bigserial primary key,
  code text not null unique,      -- e.g. "P1", "TANKER"
  name text not null,             -- display label
  is_active boolean not null default true
);

create table if not exists equipment_items (
  id bigserial primary key,
  appliance_id bigint not null references appliances(id) on delete cascade,
  name text not null,
  sort_order int not null default 0,
  unique(appliance_id, name)
);

create table if not exists job_types (
  id bigserial primary key,
  name text not null unique,
  is_active boolean not null default true
);

-- ----------------------------
-- Post-Job Checklist submissions
-- ----------------------------
create table if not exists post_job_submissions (
  id bigserial primary key,
  submitted_by_user_id bigint references users(id) on delete set null,
  submitted_at timestamptz not null default now(),

  job_date date not null,
  appliance_id bigint not null references appliances(id),

  driver_name text not null,
  job_type text not null,

  final_confirm boolean not null default false,
  notes text
);

create table if not exists post_job_submission_crew (
  submission_id bigint not null references post_job_submissions(id) on delete cascade,
  crew_name text not null,
  primary key (submission_id, crew_name)
);

create table if not exists post_job_submission_items (
  id bigserial primary key,
  submission_id bigint not null references post_job_submissions(id) on delete cascade,
  equipment_name text not null,
  status text not null check (status in ('ready','not_ready','missing','damaged','n_a')),
  note text
);

-- Helpful indexes
create index if not exists idx_post_job_submissions_job_date on post_job_submissions(job_date);
create index if not exists idx_post_job_submissions_appliance on post_job_submissions(appliance_id);
create index if not exists idx_post_job_items_submission on post_job_submission_items(submission_id);
"""

def ensure_schema():
    """
    Creates all required tables if they don't already exist.
    Safe to run on every app start.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
