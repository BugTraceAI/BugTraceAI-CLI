#!/usr/bin/env python3
"""
Search similar vulnerabilities using vector embeddings.

Usage:
    python3 search_vulns.py "SQL injection in id parameter"
    python3 search_vulns.py "XSS in search field" --limit 10
"""
import sys
import argparse
from bugtrace.core.database import get_db_manager


def search_vulnerabilities(query: str, limit: int = 5):
    """Search for similar vulnerabilities."""
    db = get_db_manager()
    
    print(f"\n🔍 Searching for: '{query}'")
    print(f"{'='*60}\n")
    
    results = db.search_similar_findings(query, limit=limit)
    
    if not results:
        print("❌ No results found. Make sure findings have been embedded first.")
        return
    
    print(f"✅ Found {len(results)} similar findings:\n")
    
    for idx, result in enumerate(results, 1):
        distance = result.get('distance', 0.0)
        similarity = max(0, 100 - (distance * 100))  # Convert distance to similarity %
        
        print(f"{idx}. [{result.get('type', 'Unknown')}] (Similarity: {similarity:.1f}%)")
        print(f"   URL: {result.get('url', 'N/A')}")
        print(f"   Parameter: {result.get('parameter', 'N/A')}")
        print(f"   Payload: {result.get('payload', 'N/A')[:80]}...")
        print(f"   Date: {result.get('timestamp', 'N/A')}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Search for similar vulnerabilities")
    parser.add_argument("query", help="Search query (e.g., 'SQL injection in id parameter')")
    parser.add_argument("--limit", type=int, default=5, help="Max results to return")
    
    args = parser.parse_args()
    
    search_vulnerabilities(args.query, args.limit)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 search_vulns.py \"search query\" [--limit N]")
        print("\nExample:")
        print("  python3 search_vulns.py \"SQL injection in id parameter\"")
        sys.exit(1)
    
    main()
