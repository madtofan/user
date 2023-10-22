-- Add migration script here
create table if not exists users
(
    id         bigint generated by default as identity,
    email      varchar     not null default '' unique,
    password   varchar     not null default '',
    first_name varchar     not null default '',
    last_name  varchar     not null default '',
    bio        varchar     not null default '',
    image      varchar     not null default '',
    token      varchar,
    verified_at timestamptz,
    created_at timestamptz not null default current_timestamp,
    updated_at timestamptz not null default current_timestamp
);

alter table users
    add constraint users_id_pk primary key (id);

create index if not exists users_email_idx on users (email);

create table if not exists roles
(
    id         bigint generated by default as identity,
    name       varchar     not null default '' unique,
    created_at timestamptz not null default current_timestamp,
    updated_at timestamptz not null default current_timestamp
);

alter table roles
    add constraint role_id_pk primary key (id);

create table if not exists permissions
(
    id         bigint generated by default as identity,
    name       varchar     not null default '' unique,
    created_at timestamptz not null default current_timestamp,
    updated_at timestamptz not null default current_timestamp
);

alter table permissions
    add constraint permission_id_pk primary key (id);

create table if not exists roles_permissions
(
    role_id       integer references roles(id),
    permission_id integer references permissions(id)
);

alter table roles_permissions
    add constraint roles_permissions_pk primary key (role_id, permission_id);

create function delete_expired_registration() returns trigger
    language plpgsql
    as $$
begin
  delete from users where verified_at is null and created_at < now() - interval '5 minute';
  return new;
end;
$$;

create trigger delete_expired_registration_trigger
    before insert on users
    execute procedure delete_expired_registration();
