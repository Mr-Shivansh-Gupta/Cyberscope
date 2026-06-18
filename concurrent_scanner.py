"""
Concurrent scanning module for Cyberscope.

Implements thread pool-based concurrent vulnerability scanning
for improved performance on large websites.

Author: Cyberscope Contributors
License: MIT
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable, Any, Optional
import logging
import time
from threading import Lock

logger = logging.getLogger(__name__)


class ConcurrentScanner:
    """
    Thread pool-based concurrent scanner wrapper.
    
    Executes scanning tasks concurrently using a configurable thread pool.
    """
    
    def __init__(self, max_workers: int = 5, timeout: int = 30) -> None:
        """
        Initialize concurrent scanner.
        
        Args:
            max_workers: Number of concurrent threads
            timeout: Timeout for thread operations
        """
        if max_workers < 1 or max_workers > 50:
            raise ValueError("max_workers must be between 1 and 50")
        
        self.max_workers: int = max_workers
        self.timeout: int = timeout
        self.executor: Optional[ThreadPoolExecutor] = None
        self.stats_lock: Lock = Lock()
        self.stats = {
            "total_tasks": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "start_time": None,
            "end_time": None,
        }
    
    def submit_task(
        self,
        func: Callable,
        *args: Any,
        **kwargs: Any
    ) -> Any:
        """
        Submit a task to the thread pool.
        
        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Future object
        """
        if self.executor is None:
            raise RuntimeError("Executor not initialized. Call execute_batch() first.")
        
        with self.stats_lock:
            self.stats["total_tasks"] += 1
        
        return self.executor.submit(func, *args, **kwargs)
    
    def execute_batch(
        self,
        tasks: List[tuple],
        progress_callback: Optional[Callable] = None
    ) -> List[Any]:
        """
        Execute a batch of tasks concurrently.
        
        Args:
            tasks: List of (func, args, kwargs) tuples
            progress_callback: Optional callback(completed, total)
            
        Returns:
            List of results
            
        Example:
            >>> scanner = ConcurrentScanner(max_workers=5)
            >>> tasks = [
            ...     (test_func, (url1,), {}),
            ...     (test_func, (url2,), {}),
            ... ]
            >>> results = scanner.execute_batch(tasks)
        """
        with self.stats_lock:
            self.stats = {
                "total_tasks": len(tasks),
                "completed_tasks": 0,
                "failed_tasks": 0,
                "start_time": time.time(),
                "end_time": None,
            }

        if not tasks:
            with self.stats_lock:
                self.stats["end_time"] = time.time()
            return []

        results = []

        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                self.executor = executor

                # Submit all tasks
                future_to_task = {
                    executor.submit(task[0], *task[1], **task[2]): task
                    for task in tasks
                }
                
                # Process completed tasks
                for future in as_completed(future_to_task):
                    try:
                        result = future.result(timeout=self.timeout)
                        results.append(result)
                        
                        with self.stats_lock:
                            self.stats["completed_tasks"] += 1
                        
                        if progress_callback:
                            progress_callback(
                                self.stats["completed_tasks"],
                                len(tasks)
                            )
                        
                    except Exception as e:
                        logger.error(f"Task failed: {e}")
                        
                        with self.stats_lock:
                            self.stats["failed_tasks"] += 1
        finally:
            with self.stats_lock:
                self.stats["end_time"] = time.time()
            self.executor = None

        return results
    
    def get_stats(self) -> dict:
        """
        Get execution statistics.
        
        Returns:
            Dictionary with stats
        """
        with self.stats_lock:
            stats_copy = self.stats.copy()
        
        # Calculate duration
        if stats_copy["start_time"] and stats_copy["end_time"]:
            stats_copy["duration"] = stats_copy["end_time"] - stats_copy["start_time"]
        
        return stats_copy
    
    def shutdown(self, wait: bool = True) -> None:
        """
        Shutdown the executor.
        
        Args:
            wait: Wait for pending tasks to complete
        """
        if self.executor:
            self.executor.shutdown(wait=wait)


class ParallelScannerEngine:
    """
    Enhanced scanner with parallel endpoint testing.
    
    Extends the base Scanner class with concurrent vulnerability testing.
    """
    
    def __init__(self, scanner: Any, max_workers: int = 5) -> None:
        """
        Initialize parallel scanner engine.
        
        Args:
            scanner: Base Scanner instance
            max_workers: Number of concurrent threads
        """
        self.scanner = scanner
        self.concurrent = ConcurrentScanner(max_workers=max_workers)
    
    def scan_endpoints_parallel(
        self,
        test_func: Callable,
        endpoints: List[str]
    ) -> tuple:
        """
        Scan multiple endpoints in parallel.
        
        Args:
            test_func: Testing function to apply to each endpoint
            endpoints: List of URLs to test
            
        Returns:
            Tuple of (results, stats)
        """
        logger.info(f"Starting parallel scan of {len(endpoints)} endpoints")
        
        # Create tasks
        tasks = [(test_func, (endpoint,), {}) for endpoint in endpoints]
        
        # Progress callback
        def progress(completed: int, total: int) -> None:
            percent = (completed / total) * 100
            logger.debug(f"Progress: {completed}/{total} ({percent:.1f}%)")
        
        # Execute
        results = self.concurrent.execute_batch(tasks, progress_callback=progress)
        stats = self.concurrent.get_stats()
        
        logger.info(
            f"Parallel scan completed: {stats['completed_tasks']} success, "
            f"{stats['failed_tasks']} failures in {stats.get('duration', 0):.2f}s"
        )
        
        return results, stats
    
    def scan_forms_parallel(self, links: List[str], payload: str) -> tuple:
        """
        Test forms across multiple links in parallel.
        
        Args:
            links: List of URLs to test
            payload: Payload to use for testing
            
        Returns:
            Tuple of (vulnerabilities_found, stats)
        """
        
        def test_forms(link: str) -> tuple:
            """Test a single link's forms."""
            try:
                forms = self.scanner.extract_forms(link)
                vulns = []
                
                for form in forms:
                    if self.scanner.test_xss_in_form(
                        form, link, custom_payload=payload
                    ):
                        vulns.append((link, "XSS"))
                    if self.scanner.test_csrf(form, link):
                        vulns.append((link, "CSRF"))
                
                return vulns
            except Exception as e:
                logger.error(f"Error testing forms at {link}: {e}")
                return []
        
        results, stats = self.scan_endpoints_parallel(test_forms, links)
        
        # Flatten results
        all_vulns = [item for result in results for item in result]
        
        return all_vulns, stats


def create_scan_tasks(
    scanner: Any,
    endpoints: List[str],
    test_types: Optional[List[str]] = None
) -> List[tuple]:
    """
    Create scan tasks for parallel execution.
    
    Args:
        scanner: Scanner instance
        endpoints: List of endpoints to test
        test_types: Types of tests to run ['xss', 'sqli', 'csrf', 'headers']
        
    Returns:
        List of task tuples
    """
    if test_types is None:
        test_types = ['xss', 'sqli', 'csrf', 'headers']
    
    tasks = []
    
    for endpoint in endpoints:
        if 'xss' in test_types and '=' in endpoint:
            tasks.append((scanner.test_xss_in_link, (endpoint,), {}))
        
        if 'sqli' in test_types and '=' in endpoint:
            tasks.append((scanner.test_sqli_in_link, (endpoint,), {}))
        
        if 'csrf' in test_types:
            forms = scanner.extract_forms(endpoint)
            if forms:
                for form in forms:
                    tasks.append((scanner.test_csrf, (form, endpoint), {}))
        
        if 'headers' in test_types:
            tasks.append((scanner.test_security_headers, (endpoint,), {}))
    
    return tasks
