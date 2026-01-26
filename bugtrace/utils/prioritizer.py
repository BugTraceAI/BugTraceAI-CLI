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
        scored_urls = []
        for url in urls:
            score = 0
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            path = parsed.path.lower()
            
            # 1. Parameter scoring
            if params:
                score += 50
                for p in params.keys():
                    if p.lower() in cls.HIGH_PRIORITY_PARAMS:
                        score += 30
                    else:
                        score += 10
            
            # 2. Path/Extension scoring
            if any(path.endswith(ext) for ext in cls.HIGH_PRIORITY_EXTENSIONS):
                score += 20
                
            if any(path.endswith(ext) for ext in cls.LOW_PRIORITY_EXTENSIONS):
                score -= 100 # Strongly deprioritize assets

            # 3. Keyword scoring in path
            high_keywords = ["login", "admin", "config", "debug", "test", "api", "v1", "v2", "upload", "download", "search"]
            for kw in high_keywords:
                if kw in path:
                    score += 15

            # 4. Short paths (homepages, category pages) are usually more interesting than deep paths
            depth = path.count("/")
            score -= (depth * 2)

            scored_urls.append((score, url))
        
        # Sort descending by score
        scored_urls.sort(key=lambda x: x[0], reverse=True)
        
        return [url for score, url in scored_urls]
