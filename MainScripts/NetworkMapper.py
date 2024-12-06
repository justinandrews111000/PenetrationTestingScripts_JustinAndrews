"""
Script Name: NetworkTopologyMapper.py
Author: Justin Andrews
Version: 1.0
Date: 2024-03-19

Description:
    Creates a network topology map using RTT measurements to estimate relative
    distances between hosts. Uses only standard Python libraries and Utils.py.

Arguments:
    network             Network range to scan (e.g., 192.168.1.0/24)
    -t, --threads      Number of threads for scanning (default: 10)
    --timeout          Timeout for each ping in seconds (default: 1)
    --samples         Number of RTT samples per host (default: 3)
    -d, --debug       Enable debug output
    -l, --logging     Enable logging to file

Usage:
    python NetworkTopologyMapper.py <network> [options]

Example:
    python NetworkTopologyMapper.py 192.168.1.0/24 -t 20 --samples 5 -d -l

GUI Parameters Start:
"network": ""
"threads": 10
"timeout": 1.0
"samples": 3,
"ms_unit": 10,
"no_ascii": false,
"debug": false,
"logging": false,
"persistent": false
GUI Parameters End:
"""

import sys
import statistics
from collections import defaultdict
from typing import Dict, List, Tuple
from Utils import LoggingPipeline, ArgumentHandler, NetworkScanner


class NetworkMapper:
    """Network topology mapping using RTT measurements."""

    def __init__(self, debug: bool = False, logging: bool = False):
        self.logger = LoggingPipeline(
            debug=debug, logging=logging, log_name="network_mapper"
        )
        self.scanner = NetworkScanner(debug=debug, logging=logging)
        self.network_data = {}

    def collect_rtt_samples(
        self, network: str, samples: int = 3, threads: int = 10, timeout: float = 1.0
    ) -> Dict[str, List[float]]:
        """Collect multiple RTT samples for each responsive host."""
        rtt_samples = defaultdict(list)

        for _ in range(samples):
            results = self.scanner.scan_network(network, timeout, threads)
            for result in results:
                if result["success"]:
                    # Extract RTT from ping output
                    try:
                        rtt = self._extract_rtt(result["output"])
                        if rtt is not None:
                            rtt_samples[result["ip"]].append(rtt)
                    except Exception as e:
                        self.logger.append_log(
                            f"Error extracting RTT for {result['ip']}: {e}", "ERROR"
                        )

        return dict(rtt_samples)

    def _extract_rtt(self, ping_output: str) -> float:
        """Extract RTT value from ping output."""
        try:
            if "time=" in ping_output:
                # Extract time value after "time=" and before "ms"
                time_str = ping_output.split("time=")[1].split("ms")[0].strip()
                return float(time_str)
            return None
        except Exception:
            return None

    def calculate_distance_metrics(
        self, rtt_samples: Dict[str, List[float]]
    ) -> Dict[str, Dict[str, float]]:
        """Calculate statistical metrics for RTT measurements."""
        metrics = {}

        for ip, samples in rtt_samples.items():
            if samples:
                metrics[ip] = {
                    "min_rtt": min(samples),
                    "max_rtt": max(samples),
                    "avg_rtt": statistics.mean(samples),
                    "median_rtt": statistics.median(samples),
                    "stdev_rtt": statistics.stdev(samples) if len(samples) > 1 else 0,
                }

        return metrics

    def cluster_hosts(
        self, metrics: Dict[str, Dict[str, float]], threshold: float = 5.0
    ) -> List[List[str]]:
        """Group hosts into clusters based on RTT similarity."""
        clusters = []
        processed = set()

        # Sort hosts by average RTT
        hosts = sorted(metrics.keys(), key=lambda x: metrics[x]["avg_rtt"])

        for host in hosts:
            if host in processed:
                continue

            # Start new cluster
            cluster = [host]
            processed.add(host)
            base_rtt = metrics[host]["avg_rtt"]

            # Find similar hosts
            for other in hosts:
                if other not in processed:
                    other_rtt = metrics[other]["avg_rtt"]
                    if abs(other_rtt - base_rtt) <= threshold:
                        cluster.append(other)
                        processed.add(other)

            clusters.append(cluster)

        return clusters

    def generate_ascii_rtt_map(
        self, metrics: Dict[str, Dict[str, float]], ms_unit: int = 10
    ) -> str:
        """Generate ASCII-based RTT distance map."""
        if not metrics:
            return "No hosts found"

        # Find max RTT and calculate height
        max_rtt = max(m["avg_rtt"] for m in metrics.values())
        height = int(max_rtt // ms_unit) + 1

        # Create the map
        output = [
            "RTT Network Distance Map (Based on ping latency)",
            "WARNING: This is an approximation based solely on RTT measurements",
            "and may not reflect actual network topology.",
            "=" * 70,
            "",
        ]

        # Group hosts by RTT units
        rtt_groups = defaultdict(list)
        for ip, data in metrics.items():
            unit = int(data["avg_rtt"] // ms_unit)
            rtt_groups[unit].append((ip, data["avg_rtt"]))

        # Generate the map lines
        ms_width = 8  # Width for ms column
        for i in range(height, -1, -1):
            ms_label = f"{i * ms_unit:>3}ms"
            line = f"{ms_label:<{ms_width}} |"

            if i in rtt_groups:
                hosts = [f"[{ip} - {rtt:.1f}ms]" for ip, rtt in sorted(rtt_groups[i])]
                line += " " + ", ".join(hosts)
            else:
                line += " #"

            output.append(line)

        return "\n".join(output)

    def generate_topology_text(
        self, clusters: List[List[str]], metrics: Dict[str, Dict[str, float]]
    ) -> str:
        """Generate text-based visualization of network topology."""
        output = ["\nNetwork Topology Map", "=" * 50, ""]

        for i, cluster in enumerate(clusters, 1):
            # Calculate average RTT for cluster
            cluster_rtts = [metrics[ip]["avg_rtt"] for ip in cluster]
            avg_cluster_rtt = statistics.mean(cluster_rtts)

            output.append(f"Cluster {i} (Avg RTT: {avg_cluster_rtt:.2f}ms):")
            output.append("-" * 40)

            for ip in sorted(cluster):
                metrics_str = (
                    f"min={metrics[ip]['min_rtt']:.2f}ms, "
                    f"avg={metrics[ip]['avg_rtt']:.2f}ms, "
                    f"max={metrics[ip]['max_rtt']:.2f}ms"
                )
                output.append(f"  {ip:<15} [{metrics_str}]")
            output.append("")

        return "\n".join(output)

    def map_network(
        self,
        network: str,
        samples: int = 3,
        threads: int = 10,
        timeout: float = 1.0,
        ms_unit: int = 10,
        no_ascii: bool = False,
    ) -> Tuple[List[List[str]], Dict[str, Dict[str, float]]]:
        """
        Map network topology using RTT measurements.

        Args:
            network: Network range to scan (CIDR notation)
            samples: Number of RTT samples per host
            threads: Number of scanner threads
            timeout: Ping timeout in seconds

        Returns:
            Tuple containing clusters and metrics
        """
        self.logger.start_section(f"Network Topology Mapping: {network}")

        # Collect RTT samples
        self.logger.append_log(f"Collecting {samples} RTT samples per host...")
        rtt_samples = self.collect_rtt_samples(network, samples, threads, timeout)

        if not rtt_samples:
            self.logger.append_log("No responsive hosts found", "WARNING")
            return [], {}

        # Calculate metrics
        metrics = self.calculate_distance_metrics(rtt_samples)

        # Cluster hosts
        clusters = self.cluster_hosts(metrics)

        # Generate and log visualizations
        topology_text = self.generate_topology_text(clusters, metrics)
        self.logger.append_log(topology_text)

        if not no_ascii:
            ascii_map = self.generate_ascii_rtt_map(metrics, ms_unit)
            self.logger.append_log("\n" + ascii_map)

        return clusters, metrics

    def cleanup(self) -> None:
        """Cleanup and finalize logging."""
        if self.logger.file_logging:
            self.logger.generate_log()


def main():
    # Define argument configuration
    arg_config = {
        "script": {
            "name": "NetworkTopologyMapper.py",
            "description": "Network Topology Mapping Utility",
        },
        "args": {
            "network": {
                "help": "Network range to scan (e.g., 192.168.1.0/24)",
                "positional": True,
            },
            "threads": {
                "flag": "-t",
                "type": int,
                "default": 10,
                "help": "Number of threads to use",
            },
            "timeout": {
                "flag": "--timeout",
                "type": float,
                "default": 1.0,
                "help": "Timeout for each ping in seconds",
            },
            "samples": {
                "flag": "--samples",
                "type": int,
                "default": 3,
                "help": "Number of RTT samples per host",
            },
            "ms_unit": {
                "flag": "--ms-unit",
                "type": int,
                "default": 10,
                "help": "RTT distance unit in milliseconds for ASCII map",
            },
            "no_ascii": {
                "flag": "--no-ascii",
                "action": "store_true",
                "help": "Disable ASCII RTT map visualization",
            },
            "debug": {
                "flag": "-d",
                "action": "store_true",
                "help": "Enable debug output",
            },
            "logging": {
                "flag": "-l",
                "action": "store_true",
                "help": "Enable logging to file",
            },
        },
    }

    # Parse arguments
    arg_handler = ArgumentHandler(arg_config)
    args = arg_handler.parse_args()

    # Initialize mapper
    mapper = NetworkMapper(debug=args.debug, logging=args.logging)

    try:
        # Map network
        mapper.map_network(
            args.network,
            samples=args.samples,
            threads=args.threads,
            timeout=args.timeout,
            ms_unit=args.ms_unit,
            no_ascii=args.no_ascii,
        )

    except Exception as e:
        mapper.logger.append_log(f"Fatal error: {str(e)}", "ERROR")
        if args.debug:
            import traceback

            mapper.logger.append_log(traceback.format_exc(), "ERROR")
        sys.exit(1)

    finally:
        mapper.cleanup()


if __name__ == "__main__":
    main()
