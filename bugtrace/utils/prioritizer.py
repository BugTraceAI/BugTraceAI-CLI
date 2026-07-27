from typing import List
from urllib.parse import urlparse, parse_qs

class URLPrioritizer:
    """
    Intelligently sorts URLs based on attack surface and likelihood of vulnerabilities.
    """
    
    HIGH_PRIORITY_PARAMS = [
        "id", "cat", "category", "page", "file", "path", "doc", "document",
        "url", "redirect", "href", "link", "search", "q", "query", "term",
        "uname", "user", "username", "pass", "password", "email", "login",
        "admin", "debug", "test", "cmd", "exec", "shell", "eval", "ip"
    ]
    
    HIGH_PRIORITY_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".cfm", ".cgi", ".pl", ".py", ".rb"]
    
    LOW_PRIORITY_EXTENSIONS = [".jpg", ".jpeg", ".png", ".gif", ".svg", ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".ico", ".pdf", ".zip", ".gz"]

    @classmethod
    def prioritize(cls, urls: List[str]) -> List[str]:
        """
        Sorts the list of URLs in place.
        """
        scored_urls = [cls._score_url(url) for url in urls]
        scored_urls.sort(key=lambda x: x[0], reverse=True)
        return [url for score, url in scored_urls]

    @classmethod
    def _score_url(cls, url: str) -> tuple:
        """Score a single URL for prioritization."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        path = parsed.path.lower()

        score = 0
        score += cls._score_parameters(params)
        score += cls._score_path_extension(path)
        score += cls._score_keywords(path)
        score += cls._score_path_depth(path)

        return (score, url)

    @classmethod
    def _score_parameters(cls, params: dict) -> int:
        """Score URL based on parameters."""
        if not params:
            return 0

        score = 50
        for p in params.keys():
            if p.lower() in cls.HIGH_PRIORITY_PARAMS:
                score += 30
            else:
                score += 10
        return score

    @classmethod
    def _score_path_extension(cls, path: str) -> int:
        """Score URL based on path extension."""
        if any(path.endswith(ext) for ext in cls.HIGH_PRIORITY_EXTENSIONS):
            return 20
        if any(path.endswith(ext) for ext in cls.LOW_PRIORITY_EXTENSIONS):
            return -100
        return 0

    @classmethod
    def _score_keywords(cls, path: str) -> int:
        """Score URL based on keywords in path."""
        high_keywords = ["login", "admin", "config", "debug", "test", "api", "v1", "v2", "upload", "download", "search"]
        score = 0
        for kw in high_keywords:
            if kw in path:
                score += 15
        return score

    @classmethod
    def _score_path_depth(cls, path: str) -> int:
        """Score URL based on path depth."""
        depth = path.count("/")
        return -(depth * 2)
