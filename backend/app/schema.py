from .db import get_conn

SCHEMA_SQL = """
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
"""

def ensure_schema():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
