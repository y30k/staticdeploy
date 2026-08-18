DROP SCHEMA public CASCADE;

--
-- PostgreSQL database dump
--
-- Captured from commit 933f5b2 with Knex 0.95.14, pg 8.7.1, and
-- PostgreSQL 13 after compiled production migrations 00.js through 02.js.
-- This fixture is immutable evidence; regenerate only through a reviewed
-- compatibility decision and update its asserted SHA-256.



SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA public;


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS 'standard public schema';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: apps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.apps (
    id character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    "defaultConfiguration" json NOT NULL,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


--
-- Name: bundles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bundles (
    id character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    tag character varying(255) NOT NULL,
    description text NOT NULL,
    hash character varying(255) NOT NULL,
    assets json NOT NULL,
    "fallbackAssetPath" character varying(255) NOT NULL,
    "fallbackStatusCode" integer NOT NULL,
    "createdAt" timestamp with time zone NOT NULL
);


--
-- Name: entrypoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.entrypoints (
    id character varying(255) NOT NULL,
    "urlMatcher" character varying(255) NOT NULL,
    "appId" character varying(255) NOT NULL,
    "bundleId" character varying(255),
    "redirectTo" character varying(255),
    configuration json,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


--
-- Name: groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups (
    id character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    roles character varying(255)[] NOT NULL,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


--
-- Name: knex_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.knex_migrations (
    id integer NOT NULL,
    name character varying(255),
    batch integer,
    migration_time timestamp with time zone
);


--
-- Name: knex_migrations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.knex_migrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: knex_migrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.knex_migrations_id_seq OWNED BY public.knex_migrations.id;


--
-- Name: knex_migrations_lock; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.knex_migrations_lock (
    index integer NOT NULL,
    is_locked integer
);


--
-- Name: knex_migrations_lock_index_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.knex_migrations_lock_index_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: knex_migrations_lock_index_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.knex_migrations_lock_index_seq OWNED BY public.knex_migrations_lock.index;


--
-- Name: operationLogs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public."operationLogs" (
    id character varying(255) NOT NULL,
    operation character varying(255) NOT NULL,
    parameters json NOT NULL,
    "performedBy" character varying(255) NOT NULL,
    "performedAt" timestamp with time zone NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id character varying(255) NOT NULL,
    idp character varying(255) NOT NULL,
    "idpId" character varying(255) NOT NULL,
    type character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


--
-- Name: users_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users_groups (
    "userId" character varying(255) NOT NULL,
    "groupId" character varying(255) NOT NULL
);


--
-- Name: knex_migrations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.knex_migrations ALTER COLUMN id SET DEFAULT nextval('public.knex_migrations_id_seq'::regclass);


--
-- Name: knex_migrations_lock index; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.knex_migrations_lock ALTER COLUMN index SET DEFAULT nextval('public.knex_migrations_lock_index_seq'::regclass);


--
-- Data for Name: apps; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.apps (id, name, "defaultConfiguration", "createdAt", "updatedAt") VALUES ('app-1', 'application-one', '{"retained":["value",1]}', '2021-11-24 23:19:33+00', '2021-11-24 23:19:33+00');


--
-- Data for Name: bundles; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.bundles (id, name, tag, description, hash, assets, "fallbackAssetPath", "fallbackStatusCode", "createdAt") VALUES ('bundle-1', 'bundle-one', 'stable', 'legacy fixture', 'sha256-fixture', '[{"path":"/index.html","mimeType":"text/html","headers":{"x-fixture":"preserved"}}]', '/index.html', 200, '2021-11-24 23:19:33+00');


--
-- Data for Name: entrypoints; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.entrypoints (id, "urlMatcher", "appId", "bundleId", "redirectTo", configuration, "createdAt", "updatedAt") VALUES ('entrypoint-1', 'fixture.example.test', 'app-1', 'bundle-1', NULL, '{"nested":{"retained":true}}', '2021-11-24 23:19:33+00', '2021-11-24 23:19:33+00');


--
-- Data for Name: groups; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.groups (id, name, roles, "createdAt", "updatedAt") VALUES ('group-1', 'Group One', '{app-manager:application-one,root}', '2021-11-24 23:19:33+00', '2021-11-24 23:19:33+00');


--
-- Data for Name: knex_migrations; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.knex_migrations (id, name, batch, migration_time) VALUES (1, '00.js', 1, '2021-11-24 23:19:33+00');
INSERT INTO public.knex_migrations (id, name, batch, migration_time) VALUES (2, '01.js', 1, '2021-11-24 23:19:33+00');
INSERT INTO public.knex_migrations (id, name, batch, migration_time) VALUES (3, '02.js', 1, '2021-11-24 23:19:33+00');


--
-- Data for Name: knex_migrations_lock; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.knex_migrations_lock (index, is_locked) VALUES (1, 0);


--
-- Data for Name: operationLogs; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public."operationLogs" (id, operation, parameters, "performedBy", "performedAt") VALUES ('operation-1', 'fixture.operation', '{"ids":["app-1","bundle-1"]}', 'fixture-user', '2021-11-24 23:19:33+00');


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.users (id, idp, "idpId", type, name, "createdAt", "updatedAt") VALUES ('user-1', 'fixture-idp', 'fixture-subject', 'user', 'Fixture User', '2021-11-24 23:19:33+00', '2021-11-24 23:19:33+00');


--
-- Data for Name: users_groups; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.users_groups ("userId", "groupId") VALUES ('user-1', 'group-1');


--
-- Name: knex_migrations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.knex_migrations_id_seq', 3, true);


--
-- Name: knex_migrations_lock_index_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.knex_migrations_lock_index_seq', 1, true);


--
-- Name: apps apps_name_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.apps
    ADD CONSTRAINT apps_name_unique UNIQUE (name);


--
-- Name: apps apps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.apps
    ADD CONSTRAINT apps_pkey PRIMARY KEY (id);


--
-- Name: bundles bundles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bundles
    ADD CONSTRAINT bundles_pkey PRIMARY KEY (id);


--
-- Name: entrypoints entrypoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entrypoints
    ADD CONSTRAINT entrypoints_pkey PRIMARY KEY (id);


--
-- Name: entrypoints entrypoints_urlmatcher_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entrypoints
    ADD CONSTRAINT entrypoints_urlmatcher_unique UNIQUE ("urlMatcher");


--
-- Name: groups groups_name_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_name_unique UNIQUE (name);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: knex_migrations_lock knex_migrations_lock_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.knex_migrations_lock
    ADD CONSTRAINT knex_migrations_lock_pkey PRIMARY KEY (index);


--
-- Name: knex_migrations knex_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.knex_migrations
    ADD CONSTRAINT knex_migrations_pkey PRIMARY KEY (id);


--
-- Name: operationLogs operationLogs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."operationLogs"
    ADD CONSTRAINT "operationLogs_pkey" PRIMARY KEY (id);


--
-- Name: users_groups users_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_groups
    ADD CONSTRAINT users_groups_pkey PRIMARY KEY ("userId", "groupId");


--
-- Name: users users_idp_idpid_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_idp_idpid_unique UNIQUE (idp, "idpId");


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: bundles_name_tag_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX bundles_name_tag_index ON public.bundles USING btree (name, tag);


--
-- Name: entrypoints_appid_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX entrypoints_appid_index ON public.entrypoints USING btree ("appId");


--
-- Name: entrypoints_bundleid_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX entrypoints_bundleid_index ON public.entrypoints USING btree ("bundleId");


--
-- Name: groups_name_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX groups_name_index ON public.groups USING btree (name);


--
-- Name: users_groups_groupid_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_groups_groupid_index ON public.users_groups USING btree ("groupId");


--
-- Name: users_groups_userid_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_groups_userid_index ON public.users_groups USING btree ("userId");


--
-- Name: entrypoints entrypoints_appid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entrypoints
    ADD CONSTRAINT entrypoints_appid_foreign FOREIGN KEY ("appId") REFERENCES public.apps(id);


--
-- Name: entrypoints entrypoints_bundleid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entrypoints
    ADD CONSTRAINT entrypoints_bundleid_foreign FOREIGN KEY ("bundleId") REFERENCES public.bundles(id);


--
-- Name: users_groups users_groups_groupid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_groups
    ADD CONSTRAINT users_groups_groupid_foreign FOREIGN KEY ("groupId") REFERENCES public.groups(id);


--
-- Name: users_groups users_groups_userid_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_groups
    ADD CONSTRAINT users_groups_userid_foreign FOREIGN KEY ("userId") REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--



SET search_path TO public;
