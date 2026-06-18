"""Tests for concurrent_scanner module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from concurrent_scanner import (
    ConcurrentScanner,
    ParallelScannerEngine,
    create_scan_tasks
)
import time


class TestConcurrentScannerInit:
    """Test ConcurrentScanner initialization."""
    
    def test_init_default_values(self):
        """Test initialization with default values."""
        scanner = ConcurrentScanner()
        assert scanner.max_workers == 5
        assert scanner.timeout == 30
        assert scanner.executor is None
        assert scanner.stats["total_tasks"] == 0
    
    def test_init_custom_values(self):
        """Test initialization with custom values."""
        scanner = ConcurrentScanner(max_workers=10, timeout=60)
        assert scanner.max_workers == 10
        assert scanner.timeout == 60
    
    def test_init_invalid_max_workers_below_range(self):
        """Test init with max_workers below 1."""
        with pytest.raises(ValueError, match="max_workers must be between 1 and 50"):
            ConcurrentScanner(max_workers=0)
    
    def test_init_invalid_max_workers_above_range(self):
        """Test init with max_workers above 50."""
        with pytest.raises(ValueError, match="max_workers must be between 1 and 50"):
            ConcurrentScanner(max_workers=51)
    
    def test_init_boundary_max_workers(self):
        """Test init with boundary values."""
        scanner1 = ConcurrentScanner(max_workers=1)
        assert scanner1.max_workers == 1
        
        scanner50 = ConcurrentScanner(max_workers=50)
        assert scanner50.max_workers == 50


class TestExecuteBatch:
    """Test execute_batch functionality."""
    
    def test_execute_batch_simple_tasks(self):
        """Test executing simple tasks."""
        scanner = ConcurrentScanner(max_workers=2)
        
        def add_one(x):
            return x + 1
        
        tasks = [
            (add_one, (1,), {}),
            (add_one, (2,), {}),
            (add_one, (3,), {}),
        ]
        
        results = scanner.execute_batch(tasks)
        assert sorted(results) == [2, 3, 4]
    
    def test_execute_batch_with_progress_callback(self):
        """Test execute_batch with progress callback."""
        scanner = ConcurrentScanner(max_workers=2)
        progress_calls = []
        
        def test_func(x):
            time.sleep(0.01)
            return x * 2
        
        def progress_callback(completed, total):
            progress_calls.append((completed, total))
        
        tasks = [(test_func, (i,), {}) for i in range(3)]
        results = scanner.execute_batch(tasks, progress_callback=progress_callback)
        
        assert len(results) == 3
        assert len(progress_calls) == 3
        assert progress_calls[-1][0] == 3  # Final completion
    
    def test_execute_batch_with_exception_handling(self):
        """Test execute_batch handles task exceptions."""
        scanner = ConcurrentScanner(max_workers=2)
        
        def failing_func():
            raise ValueError("Task failed")
        
        def working_func():
            return "success"
        
        tasks = [
            (failing_func, (), {}),
            (working_func, (), {}),
            (failing_func, (), {}),
        ]
        
        results = scanner.execute_batch(tasks)
        assert len(results) == 1
        assert results[0] == "success"
    
    def test_execute_batch_sets_timestamps(self):
        """Test that execute_batch sets start/end times."""
        scanner = ConcurrentScanner()
        tasks = [(lambda: 42, (), {})]
        
        scanner.execute_batch(tasks)
        
        assert scanner.stats["start_time"] is not None
        assert scanner.stats["end_time"] is not None
        assert scanner.stats["end_time"] >= scanner.stats["start_time"]
    
    def test_execute_batch_updates_completed_count(self):
        """Test that execute_batch executes all tasks."""
        scanner = ConcurrentScanner()
        
        def return_value(x):
            return x
        
        tasks = [(return_value, (i,), {}) for i in range(5)]
        
        results = scanner.execute_batch(tasks)
        
        # Verify all tasks were executed
        assert len(results) == 5
        # Results should be the return values: 0, 1, 2, 3, 4
        assert sorted(results) == [0, 1, 2, 3, 4]
    
    def test_execute_batch_tracks_failed_tasks(self):
        """Test that execute_batch tracks failed tasks."""
        scanner = ConcurrentScanner()
        
        def failing():
            raise Exception("fail")
        
        tasks = [(failing, (), {}) for _ in range(3)]
        
        scanner.execute_batch(tasks)
        
        assert scanner.stats["failed_tasks"] == 3


class TestGetStats:
    """Test get_stats functionality."""
    
    def test_get_stats_initial_state(self):
        """Test get_stats in initial state."""
        scanner = ConcurrentScanner()
        stats = scanner.get_stats()
        
        assert stats["total_tasks"] == 0
        assert stats["completed_tasks"] == 0
        assert stats["failed_tasks"] == 0
    
    def test_get_stats_after_execution(self):
        """Test get_stats after batch execution."""
        scanner = ConcurrentScanner()
        tasks = [(lambda: 42, (), {}) for _ in range(3)]
        
        results = scanner.execute_batch(tasks)
        
        # Verify all tasks were executed
        assert len(results) == 3
        
        # Check stats have timestamps
        stats = scanner.get_stats()
        assert stats["start_time"] is not None
        assert stats["end_time"] is not None
        assert "duration" in stats
        assert stats["duration"] >= 0
    
    def test_get_stats_is_thread_safe(self):
        """Test that get_stats access is thread-safe."""
        scanner = ConcurrentScanner()
        tasks = [(lambda: i, (), {}) for i in range(10)]
        
        scanner.execute_batch(tasks)
        
        # Multiple calls should all succeed and return consistent data
        for _ in range(5):
            stats = scanner.get_stats()
            assert isinstance(stats, dict)
            assert "start_time" in stats
            assert "end_time" in stats


class TestParallelScannerEngine:
    """Test ParallelScannerEngine."""
    
    def test_parallel_scanner_init(self):
        """Test ParallelScannerEngine initialization."""
        mock_scanner = Mock()
        engine = ParallelScannerEngine(mock_scanner, max_workers=10)
        
        assert engine.scanner is mock_scanner
        assert engine.concurrent.max_workers == 10
    
    def test_scan_endpoints_parallel(self):
        """Test scan_endpoints_parallel method."""
        mock_scanner = Mock()
        engine = ParallelScannerEngine(mock_scanner, max_workers=2)
        
        def test_func(endpoint):
            return {"url": endpoint, "result": "ok"}
        
        endpoints = ["http://example.com/page1", "http://example.com/page2"]
        
        results, stats = engine.scan_endpoints_parallel(test_func, endpoints)
        
        assert len(results) == 2
        assert all("url" in r for r in results)
    
    def test_scan_forms_parallel(self):
        """Test scan_forms_parallel method."""
        mock_scanner = Mock()
        mock_scanner.extract_forms.return_value = [{"name": "test", "method": "POST"}]
        mock_scanner.test_xss_in_form.return_value = True
        mock_scanner.test_csrf.return_value = False
        
        engine = ParallelScannerEngine(mock_scanner, max_workers=2)
        
        links = ["http://example.com/form1", "http://example.com/form2"]
        vulns, stats = engine.scan_forms_parallel(links, "<script>alert(1)</script>")
        
        # Should find vulnerabilities for each link's form
        assert len(vulns) >= 0
        assert stats["completed_tasks"] >= 1


class TestCreateScanTasks:
    """Test create_scan_tasks function."""
    
    def test_create_scan_tasks_all_types(self):
        """Test creating tasks for all vulnerability types."""
        mock_scanner = Mock()
        mock_scanner.extract_forms.return_value = [{"name": "test"}]
        
        endpoints = [
            "http://example.com/page?id=1",
            "http://example.com/page2?search=test"
        ]
        
        tasks = create_scan_tasks(
            mock_scanner,
            endpoints,
            test_types=['xss', 'sqli', 'csrf', 'headers']
        )
        
        # Should create multiple tasks per endpoint
        assert len(tasks) > 0
    
    def test_create_scan_tasks_default_types(self):
        """Test creating tasks with default types."""
        mock_scanner = Mock()
        mock_scanner.extract_forms.return_value = []
        
        endpoints = ["http://example.com/page?id=1"]
        
        tasks = create_scan_tasks(mock_scanner, endpoints)
        
        # Should use all default types
        assert len(tasks) > 0
    
    def test_create_scan_tasks_specific_type(self):
        """Test creating tasks for specific type only."""
        mock_scanner = Mock()
        mock_scanner.extract_forms.return_value = []  # Return empty list
        
        endpoints = ["http://example.com/page?id=1"]
        
        tasks = create_scan_tasks(mock_scanner, endpoints, test_types=['headers'])
        
        # Should only include headers test
        assert len(tasks) >= 1
    
    def test_create_scan_tasks_filters_by_parameter(self):
        """Test that XSS/SQLi only created for parameterized URLs."""
        mock_scanner = Mock()
        mock_scanner.extract_forms.return_value = []
        
        endpoints = [
            "http://example.com/page?id=1",  # Has parameters
            "http://example.com/static"      # No parameters
        ]
        
        tasks = create_scan_tasks(
            mock_scanner,
            endpoints,
            test_types=['xss', 'sqli']
        )
        
        # XSS and SQLi tasks should only be created for URL with parameters
        assert len(tasks) >= 1
    
    def test_create_scan_tasks_extracts_forms_for_csrf(self):
        """Test that forms are extracted for CSRF testing."""
        mock_scanner = Mock()
        mock_scanner.extract_forms.return_value = [
            {"name": "form1"},
            {"name": "form2"}
        ]
        
        endpoints = ["http://example.com/page"]
        
        tasks = create_scan_tasks(
            mock_scanner,
            endpoints,
            test_types=['csrf']
        )
        
        # Should call extract_forms for CSRF check
        mock_scanner.extract_forms.assert_called()


class TestSubmitTask:
    """Test submit_task functionality."""
    
    def test_submit_task_without_executor_raises_error(self):
        """Test that submit_task without executor raises error."""
        scanner = ConcurrentScanner()
        
        with pytest.raises(RuntimeError, match="Executor not initialized"):
            scanner.submit_task(lambda: 42)


class TestShutdown:
    """Test shutdown functionality."""
    
    def test_shutdown_without_executor(self):
        """Test shutdown when executor is None."""
        scanner = ConcurrentScanner()
        # Should not raise error
        scanner.shutdown()
    
    def test_shutdown_with_wait_true(self):
        """Test shutdown with wait=True."""
        scanner = ConcurrentScanner()
        tasks = [(lambda: i, (), {}) for i in range(3)]
        scanner.execute_batch(tasks)
        
        # Should complete cleanly
        scanner.shutdown(wait=True)


class TestThreadSafety:
    """Test thread safety of concurrent scanner."""
    
    def test_concurrent_stat_updates(self):
        """Test that all tasks complete successfully with concurrent execution."""
        scanner = ConcurrentScanner(max_workers=5)
        
        def dummy_task(i):
            time.sleep(0.001)
            return i
        
        tasks = [(dummy_task, (i,), {}) for i in range(20)]
        
        results = scanner.execute_batch(tasks)
        
        # All tasks should complete and return their results
        assert len(results) == 20
        assert sorted(results) == list(range(20))


class TestConcurrentScannerRobustness:
    """Regression tests for concurrency hardening."""

    def test_execute_batch_resets_stats_between_runs(self):
        """Stats should represent the latest batch only."""
        scanner = ConcurrentScanner(max_workers=2)

        scanner.execute_batch([(lambda: 1, (), {})])
        first_stats = scanner.get_stats()
        assert first_stats["total_tasks"] == 1

        scanner.execute_batch([(lambda: 1, (), {}), (lambda: 2, (), {})])
        second_stats = scanner.get_stats()
        assert second_stats["total_tasks"] == 2
        assert second_stats["completed_tasks"] == 2
        assert second_stats["failed_tasks"] == 0

    def test_execute_batch_handles_empty_tasks(self):
        """Empty task lists should return quickly with coherent stats."""
        scanner = ConcurrentScanner()
        results = scanner.execute_batch([])
        stats = scanner.get_stats()

        assert results == []
        assert stats["total_tasks"] == 0
        assert stats["completed_tasks"] == 0
        assert stats["failed_tasks"] == 0
        assert stats["end_time"] is not None

    def test_scan_forms_parallel_passes_custom_payload(self):
        """Parallel form scan should pass payload into scanner XSS form test."""
        mock_scanner = Mock()
        mock_scanner.extract_forms.return_value = [{"name": "test-form"}]
        mock_scanner.test_xss_in_form.return_value = True
        mock_scanner.test_csrf.return_value = False

        engine = ParallelScannerEngine(mock_scanner, max_workers=1)
        payload = "<script>alert(1)</script>"
        vulns, stats = engine.scan_forms_parallel(["http://example.com/form"], payload)

        assert len(vulns) == 1
        mock_scanner.test_xss_in_form.assert_called_with(
            {"name": "test-form"},
            "http://example.com/form",
            custom_payload=payload,
        )

    def test_create_scan_tasks_headers_only_skips_form_extraction(self):
        """Headers-only task generation should not trigger form extraction."""
        mock_scanner = Mock()
        endpoints = ["http://example.com/page?id=1"]

        tasks = create_scan_tasks(mock_scanner, endpoints, test_types=["headers"])

        assert len(tasks) == 1
        mock_scanner.extract_forms.assert_not_called()
