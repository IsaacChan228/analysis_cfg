#!/usr/bin/env python3
"""
Simplified control flow graph comparison tool
Run this script to analyze four CFG files in the graph folder
"""

from multi_comparison import MultiCFGComparator, Logger
import sys

def main():
    """Main function - simplified version"""
    print("Starting multi-tool control flow graph comparison analysis...")
    
    # Setup log output
    logger = Logger('analysis_log.txt')
    sys.stdout = logger
    
    try:
        # Create comparator and run analysis
        comparator = MultiCFGComparator()
        comparison = comparator.compare_all_cfgs()
        
        # Generate report
        report = comparator.generate_comparison_report(comparison)
        print(report)
        
        # Generate charts and CSV files
        print("\nGenerating visualization charts...")
        comparator.visualize_comparison(comparison)
        
        print("\nExporting comparison results to CSV files...")
        comparator.export_to_csv(comparison, "multi_cfg_comparison")
        
        print("\nPerforming GCC coverage analysis...")
        gcc_coverage = comparator._perform_gcc_coverage_analysis(comparison)
        if gcc_coverage:
            comparator._export_gcc_coverage_to_csv(gcc_coverage, "gcc_coverage_analysis")
            comparator._create_gcc_coverage_chart(gcc_coverage, "gcc_coverage_analysis")
        
        print("\n✅ Analysis complete!")
        print("📁 Output files:")
        print("  - analysis_log.txt (complete log)")
        print("  - result/basic_block_discovery_comparison.png (basic block discovery comparison)")
        print("  - result/control_flow_comparison.png (control flow comparison)")
        print("  - result/graph_density_comparison.png (graph density comparison)")
        print("  - result/similarity_heatmap.png (similarity heatmap)")
        print("  - result/gcc_coverage_analysis_comparison.png (GCC coverage analysis)")
        print("  - result/multi_cfg_comparison_*.csv (basic comparison data)")
        print("  - result/gcc_coverage_analysis_*.csv (GCC coverage analysis data)")
        
    except (FileNotFoundError, ValueError) as e:
        print(f"❌ Fatal error during analysis: {e}")
        print("Program cannot continue. Please check:")
        print("  1. All required CFG files exist (except angr_emul.dot and gcc.dot which are optional)")
        print("  2. CFG files are valid and contain data")
        print("  3. File paths and permissions are correct")
        return 1  # Return error code
        
    except Exception as e:
        print(f"❌ Unexpected error during analysis: {e}")
        print("This may be an internal program error, please check the logs for more information.")
        return 1  # Return error code
        
    finally:
        # Ensure log file is properly closed
        logger.close()
        sys.stdout = sys.__stdout__
        print("📊 Analysis results saved to analysis_log.txt")
    
    return 0  # Success return

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
