#!/usr/bin/env python3
"""
ClusterHound - BloodHound CE setup

Imports ClusterHound's saved Cypher queries into a BloodHound CE instance.
Run this once (or any time queries change) before ingesting ClusterHound data.

Schema registration (node icons, edge labels, is_traversable) is handled by
uploading schema.json via Administration > OpenGraph Management in the BH CE UI.
Enable OpenGraph Management first under Administration > Early Access Features.

Safe to re-run — existing queries are replaced with the latest version.
"""

import argparse
import json
import logging
import sys

import requests

log = logging.getLogger(__name__)


def parse_args():
    p = argparse.ArgumentParser(
        description="Import ClusterHound saved queries into BloodHound CE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python import_queries.py -u http://localhost:8080 -U admin -P hunter2
  python import_queries.py -u http://localhost:8080 -U admin -P hunter2 --wipe
        """,
    )
    p.add_argument("-u", "--url",          required=True, help="BloodHound CE base URL (e.g. http://localhost:8080)")
    p.add_argument("-U", "--username",     required=True, help="BloodHound username")
    p.add_argument("-P", "--password",     required=True, help="BloodHound password")
    p.add_argument("-q", "--queries-file", default="customqueries.json", help="Queries file (default: customqueries.json)")
    p.add_argument("--wipe",    action="store_true", help="Remove all existing ClusterHound saved queries before importing")
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

    def delete_saved_query(self, query_id: int) -> None:
        r = self._s.delete(
            f"{self.base}/api/v2/saved-queries/{query_id}",
            headers=self._auth(),
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


def import_queries(bh: BHSession, path: str, wipe: bool = False) -> None:
    data = load_json(path, "queries")
    queries = data.get("queries", [])
    if not queries:
        log.warning("No queries found in %s", path)
        return

    existing = {q["name"]: q["id"] for q in bh.list_saved_queries()}

    if wipe:
        ch_queries = {name: qid for name, qid in existing.items() if name.startswith("[ClusterHound]")}
        if ch_queries:
            log.info("Wiping %d existing ClusterHound query/queries...", len(ch_queries))
            for name, qid in ch_queries.items():
                bh.delete_saved_query(qid)
                log.debug("  Deleted: %s", name)
        existing = {q["name"]: q["id"] for q in bh.list_saved_queries()}

    imported = 0
    updated = 0

    log.info("Importing %d queries from %s...", len(queries), path)
    for entry in queries:
        name = entry.get("name", "")
        query_list = entry.get("queryList", [])
        if not query_list:
            continue
        query = query_list[0].get("query", "")
        if not name or not query:
            continue

        if name in existing:
            bh.delete_saved_query(existing[name])
            log.debug("  Updated: %s", name)
            updated += 1
        else:
            log.debug("  Imported: %s", name)
            imported += 1

        bh.create_saved_query(name, query)

    log.info("Done — %d imported, %d updated", imported, updated)


# ----------------------------------------------------------------------- main

def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        with BHSession(args.url) as bh:
            bh.login(args.username, args.password)
            import_queries(bh, args.queries_file, wipe=args.wipe)

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
