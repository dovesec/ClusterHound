#!/usr/bin/env python3
"""
ClusterHound - BloodHound CE setup

Registers ClusterHound's custom node/edge schema and imports saved Cypher queries
into a BloodHound CE instance. Run this once before ingesting ClusterHound data.
Safe to re-run.
"""

import argparse
import json
import logging
import sys

import requests

log = logging.getLogger(__name__)


def parse_args():
    p = argparse.ArgumentParser(
        description="Set up ClusterHound schema and queries in BloodHound CE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python configure_bloodhound.py -u http://localhost:8080 -U admin -P hunter2
  python configure_bloodhound.py -u http://localhost:8080 -U admin -P hunter2 --schema
  python configure_bloodhound.py -u http://localhost:8080 -U admin -P hunter2 --queries
  python configure_bloodhound.py -u http://localhost:8080 -U admin -P hunter2 --wipe
        """,
    )
    p.add_argument("-u", "--url",           required=True, help="BloodHound CE base URL (e.g. http://localhost:8080)")
    p.add_argument("-U", "--username",      required=True, help="BloodHound username")
    p.add_argument("-P", "--password",      required=True, help="BloodHound password")
    p.add_argument("-f", "--file",          default="model.json",         help="Schema file (default: model.json)")
    p.add_argument("-q", "--queries-file",  default="customqueries.json", help="Queries file (default: customqueries.json)")

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--schema",  action="store_true", help="Register schema only, skip queries")
    mode.add_argument("--queries", action="store_true", help="Import queries only, skip schema")

    p.add_argument("--wipe",    action="store_true", help="Remove all existing custom nodes before uploading schema")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug output")
    return p.parse_args()


class BHSession:
    """Thin authenticated session wrapper for the BloodHound CE API."""

    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self._s = requests.Session()
        self._token = None

    # ------------------------------------------------------------------ auth

    def login(self, username: str, password: str) -> None:
        r = self._s.post(
            f"{self.base}/api/v2/login",
            json={"login_method": "secret", "username": username, "secret": password},
        )
        r.raise_for_status()
        self._token = r.json()["data"]["session_token"]
        log.info("Authenticated with BloodHound CE")

    def logout(self) -> None:
        if self._token:
            try:
                self._s.post(f"{self.base}/api/v2/logout", headers=self._auth())
            except Exception:
                pass
            self._token = None

    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"}

    # --------------------------------------------------------- custom nodes

    def list_custom_nodes(self) -> list:
        r = self._s.get(f"{self.base}/api/v2/custom-nodes", headers=self._auth())
        r.raise_for_status()
        return r.json().get("data", [])

    def delete_custom_node(self, kind: str) -> None:
        r = self._s.delete(f"{self.base}/api/v2/custom-nodes/{kind}", headers=self._auth())
        r.raise_for_status()

    def push_schema(self, schema: dict) -> None:
        r = self._s.post(
            f"{self.base}/api/v2/custom-nodes",
            json=schema,
            headers={**self._auth(), "Content-Type": "application/json"},
        )
        r.raise_for_status()

    # --------------------------------------------------------- saved queries

    def list_saved_queries(self) -> list:
        r = self._s.get(f"{self.base}/api/v2/saved-queries", headers=self._auth())
        r.raise_for_status()
        return r.json().get("data", [])

    def create_saved_query(self, name: str, query: str) -> None:
        r = self._s.post(
            f"{self.base}/api/v2/saved-queries",
            json={"name": name, "query": query},
            headers={**self._auth(), "Content-Type": "application/json"},
        )
        r.raise_for_status()

    # ------------------------------------------------------- context manager

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.logout()
        self._s.close()


# ------------------------------------------------------------------ helpers

def load_json(path: str, label: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        log.error("%s file not found: %s", label, path)
        sys.exit(1)
    except json.JSONDecodeError as e:
        log.error("Invalid JSON in %s file: %s", label, e)
        sys.exit(1)


def wipe_schema(bh: BHSession) -> None:
    existing = bh.list_custom_nodes()
    if not existing:
        log.info("No existing custom nodes found")
        return
    log.info("Removing %d existing custom node(s)...", len(existing))
    for node in existing:
        kind = node.get("kindName")
        if kind:
            bh.delete_custom_node(kind)
            log.debug("  Deleted: %s", kind)


def register_schema(bh: BHSession, path: str) -> None:
    schema = load_json(path, "schema")
    log.info("Registering schema from %s...", path)
    bh.push_schema(schema)
    log.info("Schema registered successfully")


def import_queries(bh: BHSession, path: str) -> None:
    data = load_json(path, "queries")
    queries = data.get("queries", [])
    if not queries:
        log.warning("No queries found in %s", path)
        return

    existing_names = {q["name"] for q in bh.list_saved_queries()}
    skipped = 0
    imported = 0

    log.info("Importing %d queries from %s...", len(queries), path)
    for entry in queries:
        name = entry.get("name", "")
        query_list = entry.get("queryList", [])
        if not query_list:
            continue
        query = query_list[0].get("query", "")
        if not name or not query:
            continue

        if name in existing_names:
            log.debug("  Skipped (already exists): %s", name)
            skipped += 1
            continue

        bh.create_saved_query(name, query)
        log.debug("  Imported: %s", name)
        imported += 1

    log.info("Done — %d imported, %d skipped (already exist)", imported, skipped)


# ----------------------------------------------------------------------- main

def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    do_schema  = not args.queries
    do_queries = not args.schema

    try:
        with BHSession(args.url) as bh:
            bh.login(args.username, args.password)

            if do_schema:
                if args.wipe:
                    wipe_schema(bh)
                register_schema(bh, args.file)

            if do_queries:
                import_queries(bh, args.queries_file)

    except requests.HTTPError as e:
        log.error("HTTP %s: %s", e.response.status_code, e.response.text)
        sys.exit(1)
    except requests.RequestException as e:
        log.error("Connection error: %s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    main()
