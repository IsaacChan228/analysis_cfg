import re
import networkx as nx
from typing import Set, Dict, Tuple
import matplotlib.pyplot as plt
import pandas as pd
import sys

class Logger:
    """Log handler for file output"""
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log = open(filename, 'w', encoding='utf-8')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()
    
    def close(self):
        self.log.close()

class CFGNormalizer:
    """Control Flow Graph standardization processor"""
    
    # Tools that are allowed to fail without terminating the program
    OPTIONAL_TOOLS = {'angr_emul', 'gcc'}
    
    def normalize_block_name(self, name: str) -> str:
        """Standardize basic block names"""
        if not name:
            return None
        
        # Strip whitespace and normalize
        name = name.strip()
        if not name:
            return None
        
        # Remove various prefixes for addresses and labels
        name = re.sub(r'^(dbg\.|sym\.|fcn\.|reloc\.|imp\.|unk\.)', '', name)
        
        # Handle GCC basic block format (bb_N)
        if name.startswith('bb_') and name[3:].isdigit():
            return name  # Keep GCC format as-is
        
        # For CFG, we typically work with addresses as basic block identifiers
        # Keep address format but normalize it
        if re.match(r'^0x[0-9a-f]+$', name, re.IGNORECASE):
            # Normalize address format - ensure lowercase and consistent format
            return name.lower()
        
        # Remove address suffixes and labels for non-address blocks
        name = re.sub(r'\.0x[0-9a-f]+$', '', name)
        name = re.sub(r'@0x[0-9a-f]+$', '', name)
        name = re.sub(r'_0x[0-9a-f]+$', '', name)
        name = re.sub(r'\\n0x[0-9a-f]+$', '', name)  # Angr format
        
        # Remove compiler-generated suffixes
        name = re.sub(r'\.(part|isra|cold)\.[0-9]+', '', name)
        name = re.sub(r'\.(part|isra|cold)$', '', name)
        
        # Remove duplicate definition suffixes
        name = re.sub(r'_[0-9]+$', '', name)
        
        # Remove leading underscores
        name = re.sub(r'^_+', '', name)
        
        # Additional normalization to prevent duplicates
        name = name.strip()  # Remove any remaining whitespace
        
        # Handle special cases
        if name.startswith('case.') or name.startswith('switch.'):
            return name  # Keep switch cases as they are important in CFG
        
        # If name becomes empty or contains only digits, return None
        if not name or (name.isdigit() and len(name) < 4):  # Allow longer digit sequences
            return None
        
        # For CFG analysis, preserve more identifiers including labels
        return name
    
    def extract_from_dot(self, dot_file: str, tool_name: str) -> Tuple[Set[str], Set[Tuple[str, str]], str]:
        """Extract standardized basic blocks and control flow edges from DOT files"""
        basic_blocks = set()
        edges = set()
        
        try:
            with open(dot_file, 'r', encoding='utf-8') as f:
                content = f.read()
        except FileNotFoundError:
            if tool_name.lower() in self.OPTIONAL_TOOLS:
                print(f"⚠️  Warning: {tool_name} file not found ({dot_file}) - This is expected as {tool_name} may fail")
                return basic_blocks, edges, None
            else:
                print(f"❌ Fatal Error: Required {tool_name} file not found ({dot_file})")
                print(f"Program will terminate. Please ensure all required CFG files exist.")
                raise FileNotFoundError(f"Required CFG file missing: {dot_file}")
        except Exception as e:
            if tool_name.lower() in self.OPTIONAL_TOOLS:
                print(f"⚠️  Warning: Cannot read {tool_name} file ({dot_file}): {e} - Will skip this tool")
                return basic_blocks, edges, None
            else:
                print(f"❌ Fatal Error: Cannot read required {tool_name} file ({dot_file}): {e}")
                print(f"Program will terminate.")
                raise Exception(f"Failed to read required CFG file: {dot_file}")
        
        # Check if file content is empty or invalid
        if not content.strip():
            if tool_name.lower() in self.OPTIONAL_TOOLS:
                print(f"⚠️  Warning: {tool_name} file is empty or has no content - This is acceptable")
                return basic_blocks, edges, None
            else:
                print(f"❌ Fatal Error: Required {tool_name} file is empty or has no content")
                print(f"Program will terminate. Please check the CFG file generation process.")
                raise ValueError(f"Required CFG file is empty: {dot_file}")
        
        if tool_name.lower() == 'ghidra':
            basic_blocks, edges = self._extract_from_ghidra_gf(content)
        else:
            basic_blocks, edges = self._extract_from_standard_dot(content)
        
        # Find entry point for this tool
        entry_point = self.find_entry_point(content, tool_name)
        
        # Check if data was successfully extracted
        if len(basic_blocks) == 0 and len(edges) == 0:
            if tool_name.lower() in self.OPTIONAL_TOOLS:
                print(f"⚠️  Warning: {tool_name} analysis failed or found no basic blocks and control flow edges - Will continue with other tools")
                print(f"    This may be due to:")
                if tool_name.lower() == 'angr_emul':
                    print(f"    - Angr emulation mode execution failure")
                elif tool_name.lower() == 'gcc':
                    print(f"    - GCC CFG generation failure")
                    print(f"    - Missing compilation flags or debug information")
                print(f"    - Incorrect file format")
                print(f"    - Binary file too complex")
            else:
                print(f"❌ Fatal Error: Required {tool_name} found no basic blocks and control flow edges")
                print(f"    This may be due to:")
                print(f"    - Analysis tool execution failure")
                print(f"    - Incorrect file format")
                print(f"    - Binary file too complex or corrupted")
                print(f"Program will terminate.")
                raise ValueError(f"Required tool {tool_name} found no data")
        
        # Explicitly deduplicate and clean the data
        basic_blocks, edges = self._deduplicate_data(basic_blocks, edges, tool_name)
        
        return basic_blocks, edges, entry_point
    
    def _extract_from_standard_dot(self, content: str) -> Tuple[Set[str], Set[Tuple[str, str]]]:
        """Extract from standard DOT format"""
        basic_blocks = set()
        edges = set()
        
        # Extract node definitions - for CFG, nodes represent basic blocks
        # Try quoted node names first (standard DOT format)
        node_pattern = r'"([^"]+)"\s*\[.*?label="([^"]*)'
        for match in re.finditer(node_pattern, content):
            node_id = match.group(1)
            block_label = match.group(2) if match.group(2) else node_id
            
            # Handle labels containing newlines - use the first line or address
            block_label = block_label.split('\\n')[0] if '\\n' in block_label else block_label
            
            # For CFG, we prefer to use the address as the block identifier
            normalized = self.normalize_block_name(node_id)  # Use node_id which is usually the address
            if normalized:
                basic_blocks.add(normalized)
        
        # If no labeled nodes found, try to extract node names directly
        if not basic_blocks:
            simple_node_pattern = r'"([^"]+)"\s*\['
            for match in re.finditer(simple_node_pattern, content):
                block_name = match.group(1)
                normalized = self.normalize_block_name(block_name)
                if normalized:
                    basic_blocks.add(normalized)
        
        # GCC format: unquoted node names with specific patterns
        if not basic_blocks:
            gcc_node_pattern = r'(\w+)\s*\[.*?label="([^"]*)'
            for match in re.finditer(gcc_node_pattern, content):
                node_id = match.group(1)
                block_label = match.group(2) if match.group(2) else node_id
                
                # GCC uses patterns like fn_72_basic_block_68
                if 'basic_block' in node_id:
                    # Extract the basic block number/identifier
                    bb_match = re.search(r'basic_block_(\d+)', node_id)
                    if bb_match:
                        bb_num = bb_match.group(1)
                        normalized = self.normalize_block_name(f"bb_{bb_num}")
                        if normalized:
                            basic_blocks.add(normalized)
        
        # Extract edges (control flow relationships)
        # Standard DOT format with quoted names
        edge_pattern = r'"([^"]+)"\s*->\s*"([^"]+)"'
        for match in re.finditer(edge_pattern, content):
            source = match.group(1)
            target = match.group(2)
            
            # Normalize block identifiers
            source_normalized = self.normalize_block_name(source)
            target_normalized = self.normalize_block_name(target)
            
            if source_normalized and target_normalized:
                edges.add((source_normalized, target_normalized))
        
        # GCC format: unquoted names with port specifications (e.g., fn_72_basic_block_0:s -> fn_72_basic_block_2:n)
        gcc_edge_pattern = r'(\w+)(?::\w+)?\s*->\s*(\w+)(?::\w+)?'
        for match in re.finditer(gcc_edge_pattern, content):
            source = match.group(1)
            target = match.group(2)
            
            # Only process if they look like GCC basic block identifiers
            if 'basic_block' in source and 'basic_block' in target:
                # Extract basic block numbers
                source_bb = re.search(r'basic_block_(\d+)', source)
                target_bb = re.search(r'basic_block_(\d+)', target)
                
                if source_bb and target_bb:
                    source_normalized = self.normalize_block_name(f"bb_{source_bb.group(1)}")
                    target_normalized = self.normalize_block_name(f"bb_{target_bb.group(1)}")
                    
                    if source_normalized and target_normalized:
                        edges.add((source_normalized, target_normalized))
        
        return basic_blocks, edges
    
    def _extract_from_ghidra_gf(self, content: str) -> Tuple[Set[str], Set[Tuple[str, str]]]:
        """Extract from Ghidra GF format"""
        basic_blocks = set()
        edges = set()
        
        # Extract node definitions - Ghidra format: "address" [ label="block_label" VertexType="Entry" ];
        node_pattern = r'"([^"]+)"\s*\[\s*label="([^"]+)"'
        for match in re.finditer(node_pattern, content):
            address = match.group(1)
            block_label = match.group(2)
            
            # For CFG, use address as the primary identifier
            normalized = self.normalize_block_name(address)
            if normalized:
                basic_blocks.add(normalized)
        
        # Extract edges (control flow relationships) - Format: "address1" -> "address2";
        edge_pattern = r'"([^"]+)"\s*->\s*"([^"]+)"'
        
        # Extract control flow relationships
        for match in re.finditer(edge_pattern, content):
            source_addr = match.group(1)
            target_addr = match.group(2)
            
            source_normalized = self.normalize_block_name(source_addr)
            target_normalized = self.normalize_block_name(target_addr)
            
            if source_normalized and target_normalized:
                edges.add((source_normalized, target_normalized))
        
        return basic_blocks, edges
    
    def _deduplicate_data(self, basic_blocks: Set[str], edges: Set[Tuple[str, str]], tool_name: str) -> Tuple[Set[str], Set[Tuple[str, str]]]:
        """Explicitly deduplicate basic blocks and edges with logging"""
        original_block_count = len(basic_blocks)
        original_edge_count = len(edges)
        
        # Convert to set to ensure deduplication (even though they should already be sets)
        deduplicated_blocks = set(basic_blocks)
        deduplicated_edges = set(edges)
        
        # Remove any self-loops (block pointing to itself) as they might be artifacts
        filtered_edges = set()
        self_loop_count = 0
        for source, target in deduplicated_edges:
            if source == target:
                self_loop_count += 1
            else:
                filtered_edges.add((source, target))
        
        final_block_count = len(deduplicated_blocks)
        final_edge_count = len(filtered_edges)
        
        # Log deduplication results if any duplicates were found
        if original_block_count != final_block_count:
            print(f"  🔧 {tool_name}: Removed {original_block_count - final_block_count} duplicate basic blocks")
        
        if original_edge_count != final_edge_count + self_loop_count:
            print(f"  🔧 {tool_name}: Removed {original_edge_count - final_edge_count - self_loop_count} duplicate edges")
        
        if self_loop_count > 0:
            print(f"  🔧 {tool_name}: Removed {self_loop_count} self-loops")
        
        return deduplicated_blocks, filtered_edges

    def find_entry_point(self, content: str, tool_name: str) -> str:
        """Find the main function entry point for each tool"""
        tool_name_lower = tool_name.lower()
        
        if tool_name_lower == 'gcc':
            # GCC: Look for ENTRY node or first node in main cluster
            entry_match = re.search(r'(fn_\d+_basic_block_\d+)\s*\[.*?label="ENTRY"', content)
            if entry_match:
                bb_match = re.search(r'basic_block_(\d+)', entry_match.group(1))
                if bb_match:
                    return f"bb_{bb_match.group(1)}"
            
            # Fallback: look for first basic block in main cluster
            main_cluster_match = re.search(r'subgraph\s+"?cluster_main"?.*?fn_\d+_basic_block_(\d+)', content, re.DOTALL)
            if main_cluster_match:
                return f"bb_{main_cluster_match.group(1)}"
                
        elif tool_name_lower == 'ghidra':
            # Ghidra: Look for main symbol or first address
            main_match = re.search(r'"([^"]+)"\s*\[.*?Symbols="main"', content)
            if main_match:
                return self.normalize_block_name(main_match.group(1))
            
            # Fallback: first node in the graph
            first_node_match = re.search(r'"([^"]+)"\s*\[', content)
            if first_node_match:
                return self.normalize_block_name(first_node_match.group(1))
                
        elif tool_name_lower.startswith('angr') or tool_name_lower == 'radare2':
            # Angr/Radare2: Look for main comments or first node
            main_comment_match = re.search(r'"([^"]+)"\s*\[.*?main', content, re.IGNORECASE)
            if main_comment_match:
                return self.normalize_block_name(main_comment_match.group(1))
            
            # Look for first node that looks like a main address (common pattern: 0x4xxxxx)
            first_main_addr = re.search(r'"(0x[4-6][0-9a-f]{5,})"', content)
            if first_main_addr:
                return self.normalize_block_name(first_main_addr.group(1))
            
            # Fallback: first node in the graph
            first_node_match = re.search(r'"([^"]+)"\s*\[', content)
            if first_node_match:
                return self.normalize_block_name(first_node_match.group(1))
        
        return None
class MultiCFGComparator:
    """Multi control flow graph comparison analyzer"""
    
    def __init__(self):
        self.normalizer = CFGNormalizer()
        self.tools = {
            'Radare2': 'graph/r2.dot',
            'Ghidra': 'graph/ghidra.gf',
            'Angr_Fast': 'graph/angr_fast.dot', 
            'Angr_Emul': 'graph/angr_emul.dot',
            'GCC': 'graph/gcc.dot'
        }
        
    def compare_all_cfgs(self) -> Dict:
        """Compare all CFG files"""
        print("Starting analysis of all control flow graphs...")
        
        tool_data = {}
        
        # Extract data from each tool
        for tool_name, file_path in self.tools.items():
            print(f"Standardizing {tool_name} control flow graph...")
            try:
                basic_blocks, edges, entry_point = self.normalizer.extract_from_dot(file_path, tool_name)
                tool_data[tool_name] = {
                    'basic_blocks': basic_blocks,
                    'edges': edges,
                    'entry_point': entry_point,
                    'graph': self._create_graph(basic_blocks, edges)
                }
                entry_info = f" (entry: {entry_point})" if entry_point else " (no entry point)"
                print(f"{tool_name}: {len(basic_blocks)} basic blocks, {len(edges)} control flow edges{entry_info}")
            except (FileNotFoundError, ValueError, Exception) as e:
                if tool_name.lower() in self.normalizer.OPTIONAL_TOOLS:
                    # Optional tool failure is acceptable, create empty data
                    print(f"⚠️  {tool_name} skipped: {str(e)}")
                    tool_data[tool_name] = {
                        'basic_blocks': set(),
                        'edges': set(),
                        'entry_point': None,
                        'graph': self._create_graph(set(), set())
                    }
                    print(f"{tool_name}: 0 basic blocks, 0 control flow edges (skipped)")
                else:
                    # Required tool failures terminate the program
                    print(f"💥 Program terminated: {tool_name} is a required tool but analysis failed")
                    raise e
        
        # Verify at least one successful tool (except angr_emul)
        successful_tools = []
        for tool_name, data in tool_data.items():
            if len(data['basic_blocks']) > 0 or len(data['edges']) > 0:
                successful_tools.append(tool_name)
        
        if len(successful_tools) < 2:
            error_msg = f"❌ Fatal error: Less than 2 successful tools ({len(successful_tools)} successful)"
            print(error_msg)
            print("At least 2 tools must succeed for meaningful comparison.")
            raise ValueError(error_msg)
        
        print(f"✅ Successfully analyzed {len(successful_tools)} tools: {', '.join(successful_tools)}")
        
        # Calculate union and intersection of all tools with explicit deduplication
        all_basic_blocks = set()
        all_edges = set()
        
        print(f"\n🔍 Aggregating data from all tools:")
        for tool_name, data in tool_data.items():
            before_block_count = len(all_basic_blocks)
            before_edge_count = len(all_edges)
            
            all_basic_blocks |= data['basic_blocks']
            all_edges |= data['edges']
            
            blocks_added = len(all_basic_blocks) - before_block_count
            edges_added = len(all_edges) - before_edge_count
            
            if blocks_added > 0 or edges_added > 0:
                print(f"  + {tool_name}: Added {blocks_added} unique basic blocks, {edges_added} unique edges")
        
        print(f"📊 Total unique basic blocks: {len(all_basic_blocks)}")
        print(f"📊 Total unique edges: {len(all_edges)}")
        
        # Calculate intersection with explicit logging
        common_basic_blocks = all_basic_blocks.copy()
        common_edges = all_edges.copy()
        
        print(f"\n🔍 Finding common elements across tools:")
        for tool_name, data in tool_data.items():
            before_common_blocks = len(common_basic_blocks)
            before_common_edges = len(common_edges)
            
            common_basic_blocks &= data['basic_blocks']
            common_edges &= data['edges']
            
            blocks_removed = before_common_blocks - len(common_basic_blocks)
            edges_removed = before_common_edges - len(common_edges)
            
            if blocks_removed > 0 or edges_removed > 0:
                print(f"  - {tool_name}: Filtered out {blocks_removed} basic blocks, {edges_removed} edges not in common")
        
        print(f"📊 Common basic blocks: {len(common_basic_blocks)}")
        print(f"📊 Common edges: {len(common_edges)}")
        
        # Final validation - ensure no duplicates in the final results
        print(f"\n✅ Final validation:")
        print(f"  - All basic blocks are unique: {len(all_basic_blocks) == len(set(all_basic_blocks))}")
        print(f"  - All edges are unique: {len(all_edges) == len(set(all_edges))}")
        print(f"  - Common basic blocks are unique: {len(common_basic_blocks) == len(set(common_basic_blocks))}")
        print(f"  - Common edges are unique: {len(common_edges) == len(set(common_edges))}")
        
        return {
            'tool_data': tool_data,
            'all_basic_blocks': all_basic_blocks,
            'all_edges': all_edges,
            'common_basic_blocks': common_basic_blocks,
            'common_edges': common_edges
        }
    
    def _create_graph(self, basic_blocks: Set[str], edges: Set[Tuple[str, str]]) -> nx.DiGraph:
        """Create NetworkX directed graph"""
        G = nx.DiGraph()
        G.add_nodes_from(basic_blocks)
        G.add_edges_from(edges)
        return G
    

    
    def _calculate_graph_metrics(self, graph: nx.DiGraph) -> Dict:
        """Calculate graph structure metrics"""
        if graph.number_of_nodes() == 0:
            return {
                'nodes': 0,
                'edges': 0,
                'avg_in_degree': 0,
                'avg_out_degree': 0,
                'max_in_degree': 0, 
                'max_out_degree': 0,
                'density': 0,
                'strongly_connected_components': 0
            }
        
        in_degrees = dict(graph.in_degree())
        out_degrees = dict(graph.out_degree())
        
        return {
            'nodes': graph.number_of_nodes(),
            'edges': graph.number_of_edges(),
            'avg_in_degree': sum(in_degrees.values()) / graph.number_of_nodes(),
            'avg_out_degree': sum(out_degrees.values()) / graph.number_of_nodes(),
            'max_in_degree': max(in_degrees.values()) if in_degrees else 0,
            'max_out_degree': max(out_degrees.values()) if out_degrees else 0,
            'density': nx.density(graph),
            'strongly_connected_components': len(list(nx.strongly_connected_components(graph)))
        }
    
    def _get_structural_metrics(self, graph: nx.DiGraph) -> Dict:
        """Get comprehensive structural metrics for a graph"""
        if graph.number_of_nodes() == 0:
            return {
                'nodes': 0, 'edges': 0, 'density': 0, 'avg_degree': 0,
                'max_degree': 0, 'strongly_connected_components': 0
            }
        
        degrees = [d for n, d in graph.degree()]
        
        return {
            'nodes': graph.number_of_nodes(),
            'edges': graph.number_of_edges(),
            'density': nx.density(graph),
            'avg_degree': sum(degrees) / len(degrees) if degrees else 0,
            'max_degree': max(degrees) if degrees else 0,
            'strongly_connected_components': len(list(nx.strongly_connected_components(graph)))
        }
    
    def generate_comparison_report(self, comparison: Dict) -> str:
        """Generate detailed comparison report"""
        tool_data = comparison['tool_data']
        
        report = []
        report.append("=" * 80)
        report.append("Multi-Tool Control Flow Graph Comparison Analysis Report")
        report.append("=" * 80)
        
        # Basic statistics
        report.append("\n1. Basic Statistics")
        report.append("-" * 50)
        report.append(f"{'Tool':<15} {'Basic Blocks':<15} {'Edges':<15} {'Graph Density':<15} {'Status':<10}")
        report.append("-" * 75)
        
        failed_tools = []
        for tool_name, data in tool_data.items():
            metrics = self._calculate_graph_metrics(data['graph'])
            block_count = len(data['basic_blocks'])
            edge_count = len(data['edges'])
            
            # Determine if tool succeeded
            status = "✓ Success" if block_count > 0 or edge_count > 0 else "✗ Failed"
            if block_count == 0 and edge_count == 0:
                failed_tools.append(tool_name)
            
            report.append(f"{tool_name:<15} {block_count:<15} {edge_count:<15} {metrics['density']:<15.4f} {status:<10}")
        
        # Add explanation for failed tools
        if failed_tools:
            report.append(f"\n⚠️  Failed analysis tools: {', '.join(failed_tools)}")
            report.append("   These tools may have failed due to:")
            report.append("   - Tool execution failure or timeout")
            report.append("   - Unsupported binary file format")
            report.append("   - Configuration or environment issues")
        
        # Basic block discovery comparison
        report.append(f"\n2. Basic Block Discovery Analysis")
        report.append("-" * 50)
        report.append(f"Total unique basic blocks: {len(comparison['all_basic_blocks'])}")
        report.append(f"Basic blocks found by all tools: {len(comparison['common_basic_blocks'])}")
        
        # Pairwise comparison (only successful tools) - using structural similarity
        successful_tools = [tool for tool in tool_data.keys() if tool not in failed_tools]
        if len(successful_tools) >= 2:
            report.append(f"\n3. Pairwise Structural Similarity Analysis (Successful Tools Only)")
            report.append("-" * 50)
            
            for i, tool1 in enumerate(successful_tools):
                for j, tool2 in enumerate(successful_tools[i+1:], i+1):
                    graph1 = tool_data[tool1]['graph']
                    graph2 = tool_data[tool2]['graph']
                    entry1 = tool_data[tool1]['entry_point']
                    entry2 = tool_data[tool2]['entry_point']
                    structural_similarity = self._calculate_pivot_structural_similarity(graph1, graph2, entry1, entry2)
                    
                    report.append(f"{tool1} vs {tool2}:")
                    if structural_similarity is not None:
                        report.append(f"  Structural similarity: {structural_similarity:.3f}")
                    else:
                        report.append(f"  Structural similarity: N/A (missing entry points)")
        else:
            report.append(f"\n3. Pairwise Structural Similarity Analysis")
            report.append("-" * 50)
            report.append("⚠️  Less than 2 successful tools, cannot perform meaningful comparison")
        
        # Control flow analysis
        report.append(f"\n4. Control Flow Analysis")
        report.append("-" * 50)
        report.append(f"Total unique control flow edges: {len(comparison['all_edges'])}")
        report.append(f"Control flow edges found by all tools: {len(comparison['common_edges'])}")
        
        # Detailed tool characteristic analysis (successful tools only)
        if successful_tools:
            report.append(f"\n5. Tool Characteristic Analysis (Successful Tools Only)")
            report.append("-" * 50)
            
            for tool_name in successful_tools:
                data = tool_data[tool_name]
                # Calculate basic blocks unique to this tool (not found by any other successful tool)
                unique_blocks = data['basic_blocks'].copy()
                for other_tool in successful_tools:
                    if other_tool != tool_name:
                        unique_blocks -= tool_data[other_tool]['basic_blocks']
                
                report.append(f"\n{tool_name} unique basic blocks ({len(unique_blocks)} total):")
                if len(unique_blocks) > 0:
                    for block in sorted(list(unique_blocks))[:10]:
                        report.append(f"  - {block}")
                    if len(unique_blocks) > 10:
                        report.append(f"  ... and {len(unique_blocks) - 10} more")
                else:
                    report.append("  (No unique basic blocks)")
        
        return "\n".join(report)

    def visualize_comparison(self, comparison: Dict):
        """Visualize comparison results"""
        tool_data = comparison['tool_data']
        
        # Identify failed tools
        failed_tools = []
        for tool_name, data in tool_data.items():
            if len(data['basic_blocks']) == 0 and len(data['edges']) == 0:
                failed_tools.append(tool_name)

        tools = list(tool_data.keys())
        colors = ['#ff7f0e', '#9467bd', '#2ca02c', '#d62728', '#17becf']
        
        # Use gray color for failed tools
        bar_colors = []
        for i, tool in enumerate(tools):
            if tool in failed_tools:
                bar_colors.append('#cccccc')
            else:
                bar_colors.append(colors[i % len(colors)])
        
        # Create charts
        self._create_basic_block_discovery_chart(tool_data, tools, bar_colors, failed_tools)
        self._create_control_flow_chart(tool_data, tools, bar_colors, failed_tools)
        self._create_graph_density_chart(tool_data, tools, bar_colors, failed_tools)
        self._create_similarity_heatmap(tool_data, failed_tools)
        
        # Export data to CSV
        self.export_to_csv(comparison)
    
    def _create_basic_block_discovery_chart(self, tool_data, tools, bar_colors, failed_tools):
        """Create basic block discovery comparison chart"""
        fig, ax = plt.subplots(1, 1, figsize=(12, 6))
        
        # Total basic block count comparison
        self._create_bar_chart(ax, tools, 
                              [len(data['basic_blocks']) for data in tool_data.values()],
                              bar_colors, failed_tools, 'Basic Block Discovery Comparison', 'Number of Basic Blocks')
        
        plt.tight_layout()
        plt.savefig('result/basic_block_discovery_comparison.png', dpi=300, bbox_inches='tight')
        print("Basic block discovery comparison chart saved as result/basic_block_discovery_comparison.png")

    def _create_control_flow_chart(self, tool_data, tools, bar_colors, failed_tools):
        """Create control flow comparison chart"""
        fig, ax = plt.subplots(1, 1, figsize=(12, 6))
        
        # Total control flow edge comparison
        self._create_bar_chart(ax, tools,
                              [len(data['edges']) for data in tool_data.values()],
                              bar_colors, failed_tools, 'Control Flow Edge Comparison', 'Number of Edges')
        
        plt.tight_layout()
        plt.savefig('result/control_flow_comparison.png', dpi=300, bbox_inches='tight')
        print("Control flow comparison chart saved as result/control_flow_comparison.png")

    def _create_graph_density_chart(self, tool_data, tools, bar_colors, failed_tools):
        """Create graph density comparison chart"""
        fig, ax = plt.subplots(1, 1, figsize=(12, 6))
        
        # Total graph density comparison
        densities = [self._calculate_graph_metrics(data['graph'])['density'] for data in tool_data.values()]
        self._create_bar_chart(ax, tools, densities, bar_colors, failed_tools, 
                              'Graph Density Comparison', 'Graph Density', format_values=True)
        
        plt.tight_layout()
        plt.savefig('result/graph_density_comparison.png', dpi=300, bbox_inches='tight')
        print("Graph density comparison chart saved as result/graph_density_comparison.png")

    def _create_bar_chart(self, ax, tools, values, colors, failed_tools, title, ylabel, format_values=False):
        """Helper function to create bar charts"""
        bars = ax.bar(tools, values, color=colors)
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_ylabel(ylabel)
        ax.set_xlabel('Tools')
        
        # Add value labels and failure markers
        max_val = max(values) if values else 1
        for i, (bar, value, tool) in enumerate(zip(bars, values, tools)):
            if tool in failed_tools:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max_val*0.02,
                       'FAILED', ha='center', va='bottom', fontweight='bold', color='red', fontsize=8)
            
            if format_values:
                label = f'{value:.4f}'
            else:
                label = str(int(value))
                
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max_val*0.01,
                   label, ha='center', va='bottom', fontweight='bold', fontsize=10)
    
    def _create_similarity_heatmap(self, tool_data, failed_tools):
        """Create similarity heatmap based on graph structure comparison"""
        fig, ax = plt.subplots(1, 1, figsize=(10, 8))
        
        tools = list(tool_data.keys())
        n_tools = len(tools)
        similarity_matrix = [[0 for _ in range(n_tools)] for _ in range(n_tools)]
        
        for i, tool1 in enumerate(tools):
            for j, tool2 in enumerate(tools):
                if i == j:
                    similarity_matrix[i][j] = 1.0
                elif tool1 in failed_tools or tool2 in failed_tools:
                    similarity_matrix[i][j] = -1
                else:
                    # Use structural similarity with entry point pivot
                    graph1 = tool_data[tool1]['graph']
                    graph2 = tool_data[tool2]['graph']
                    entry1 = tool_data[tool1]['entry_point']
                    entry2 = tool_data[tool2]['entry_point']
                    structural_similarity = self._calculate_pivot_structural_similarity(graph1, graph2, entry1, entry2)
                    if structural_similarity is not None:
                        similarity_matrix[i][j] = structural_similarity
                    else:
                        similarity_matrix[i][j] = -1  # Mark as N/A like failed tools
        
        # Create custom colormap to handle failures and improve high similarity visibility
        import matplotlib.colors as mcolors
        import numpy as np
        
        # Replace -1 values with NaN for display
        display_matrix = np.array(similarity_matrix, dtype=float)
        display_matrix[display_matrix == -1] = np.nan
        
        # Use 'viridis' colormap which provides better contrast at high values
        # Or use custom color mapping from light to medium intensity blues, avoiding too dark
        colors = ['#ffffff', '#f0f8ff', '#e6f3ff', '#cce7ff', '#99d6ff', '#66c2ff', '#3399ff', '#0066cc', '#004d99']
        custom_cmap = mcolors.LinearSegmentedColormap.from_list('light_blues', colors, N=256)
        
        im = ax.imshow(display_matrix, cmap=custom_cmap, aspect='auto', vmin=0, vmax=1)
        ax.set_title('Control Flow Graph Structural Similarity', fontsize=16, fontweight='bold')
        ax.set_xticks(range(n_tools))
        ax.set_yticks(range(n_tools))
        ax.set_xticklabels(tools, rotation=45)
        ax.set_yticklabels(tools)
        
        # Add value labels with intelligent color selection for readability
        for i in range(n_tools):
            for j in range(n_tools):
                if similarity_matrix[i][j] == -1:
                    ax.text(j, i, 'N/A', ha='center', va='center', fontweight='bold', color='red')
                else:
                    # Choose text color based on background color
                    value = similarity_matrix[i][j]
                    # Use white text when similarity > 0.5, otherwise use black
                    text_color = 'white' if value > 0.5 else 'black'
                    ax.text(j, i, f'{value:.3f}',
                            ha='center', va='center', fontweight='bold', color=text_color)
        
        # Add colorbar with labels
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label('Structural Similarity', rotation=270, labelpad=20)
        
        plt.tight_layout()
        plt.savefig('result/similarity_heatmap.png', dpi=300, bbox_inches='tight')
        print("Similarity heatmap saved as result/similarity_heatmap.png")
    
    def export_to_csv(self, comparison: Dict, output_prefix: str = "multi_cfg_comparison"):
        """Export comparison results to CSV files"""
        tool_data = comparison['tool_data']
        
        # Identify failed tools
        failed_tools = []
        for tool_name, data in tool_data.items():
            if len(data['basic_blocks']) == 0 and len(data['edges']) == 0:
                failed_tools.append(tool_name)
        
        # 1. Export basic statistics
        stats_data = []
        for tool_name, data in tool_data.items():
            metrics = self._calculate_graph_metrics(data['graph'])
            status = "Failed" if tool_name in failed_tools else "Success"
            stats_data.append({
                'Tool': tool_name,
                'Status': status,
                'Basic Block Count': len(data['basic_blocks']),
                'Control Flow Edge Count': len(data['edges']),
                'Average In-Degree': round(metrics['avg_in_degree'], 3),
                'Average Out-Degree': round(metrics['avg_out_degree'], 3),
                'Max In-Degree': metrics['max_in_degree'],
                'Max Out-Degree': metrics['max_out_degree'],
                'Graph Density': round(metrics['density'], 6),
                'Strong Components': metrics['strongly_connected_components']
            })
        
        stats_df = pd.DataFrame(stats_data)
        stats_df.to_csv(f"result/{output_prefix}_statistics.csv", index=False, encoding='utf-8')
        
        # 2. Export structural similarity matrix
        tools = list(tool_data.keys())
        similarity_data = []
        
        for tool1 in tools:
            row = {'Tool': tool1}
            for tool2 in tools:
                if tool1 == tool2:
                    row[tool2] = 1.0
                elif tool1 in failed_tools or tool2 in failed_tools:
                    row[tool2] = 'N/A'  # Mark failed tools as N/A
                else:
                    graph1 = tool_data[tool1]['graph']
                    graph2 = tool_data[tool2]['graph']
                    entry1 = tool_data[tool1]['entry_point']
                    entry2 = tool_data[tool2]['entry_point']
                    structural_similarity = self._calculate_pivot_structural_similarity(graph1, graph2, entry1, entry2)
                    if structural_similarity is not None:
                        row[tool2] = round(structural_similarity, 4)
                    else:
                        row[tool2] = 'N/A'
            similarity_data.append(row)
        
        similarity_df = pd.DataFrame(similarity_data)
        similarity_df.to_csv(f"result/{output_prefix}_similarity.csv", index=False, encoding='utf-8')
        
        # 3. Export Entry Point Neighborhood Similarity matrix
        entry_neighborhood_matrix_data = []
        tools = list(tool_data.keys())
        
        for tool1 in tools:
            row = {'Tool': tool1}
            for tool2 in tools:
                if tool1 == tool2:
                    row[tool2] = 1.0
                elif tool1 in failed_tools or tool2 in failed_tools:
                    row[tool2] = 'N/A'
                else:
                    graph1 = tool_data[tool1]['graph']
                    graph2 = tool_data[tool2]['graph']
                    entry1 = tool_data[tool1]['entry_point']
                    entry2 = tool_data[tool2]['entry_point']
                    
                    # Check if both graphs have valid entry points
                    if (entry1 and entry2 and entry1 in graph1.nodes() and entry2 in graph2.nodes() and 
                        graph1.number_of_nodes() > 0 and graph2.number_of_nodes() > 0):
                        entry_similarity = self._compare_entry_neighborhoods(graph1, graph2, entry1, entry2)
                        row[tool2] = round(entry_similarity, 4)
                    else:
                        row[tool2] = 'N/A'
            entry_neighborhood_matrix_data.append(row)
        
        entry_neighborhood_df = pd.DataFrame(entry_neighborhood_matrix_data)
        entry_neighborhood_df.to_csv(f"result/{output_prefix}_entry_neighborhood_similarity.csv", index=False, encoding='utf-8')
        
        # 4. Export Path Structure Similarity matrix
        path_structure_matrix_data = []
        
        for tool1 in tools:
            row = {'Tool': tool1}
            for tool2 in tools:
                if tool1 == tool2:
                    row[tool2] = 1.0
                elif tool1 in failed_tools or tool2 in failed_tools:
                    row[tool2] = 'N/A'
                else:
                    graph1 = tool_data[tool1]['graph']
                    graph2 = tool_data[tool2]['graph']
                    entry1 = tool_data[tool1]['entry_point']
                    entry2 = tool_data[tool2]['entry_point']
                    
                    # Check if both graphs have valid entry points
                    if (entry1 and entry2 and entry1 in graph1.nodes() and entry2 in graph2.nodes() and 
                        graph1.number_of_nodes() > 0 and graph2.number_of_nodes() > 0):
                        path_similarity = self._compare_path_structures(graph1, graph2, entry1, entry2)
                        row[tool2] = round(path_similarity, 4)
                    else:
                        row[tool2] = 'N/A'
            path_structure_matrix_data.append(row)
        
        path_structure_df = pd.DataFrame(path_structure_matrix_data)
        path_structure_df.to_csv(f"result/{output_prefix}_path_structure_similarity.csv", index=False, encoding='utf-8')
        
        print(f"Comparison results exported to:")
        print(f"  - result/{output_prefix}_statistics.csv")
        print(f"  - result/{output_prefix}_similarity.csv")
        print(f"  - result/{output_prefix}_entry_neighborhood_similarity.csv")
        print(f"  - result/{output_prefix}_path_structure_similarity.csv")
        
        if failed_tools:
            print(f"⚠️  Note: {', '.join(failed_tools)} tool analysis failed, marked as 'N/A' in CSV files")
    

    
    def _calculate_pivot_structural_similarity(self, graph1: nx.DiGraph, graph2: nx.DiGraph, entry1: str, entry2: str):
        """Calculate structural similarity using entry points as pivot for alignment"""
        # If either graph is empty, return None (N/A)
        if graph1.number_of_nodes() == 0 or graph2.number_of_nodes() == 0:
            return None
        
        # Only use pivot-based comparison if both have valid entry points
        if entry1 and entry2 and entry1 in graph1.nodes() and entry2 in graph2.nodes():
            return self._calculate_pivot_based_similarity(graph1, graph2, entry1, entry2)
        else:
            # Return None (N/A) if no valid entry points
            return None
    
    def _calculate_pivot_based_similarity(self, graph1: nx.DiGraph, graph2: nx.DiGraph, entry1: str, entry2: str) -> float:
        """Calculate similarity using entry points as alignment pivots"""
        similarities = []
        
        # 1. Basic graph metrics similarity (same as before)
        metrics1 = self._get_structural_metrics(graph1)
        metrics2 = self._get_structural_metrics(graph2)
        
        max_nodes = max(metrics1['nodes'], metrics2['nodes'])
        min_nodes = min(metrics1['nodes'], metrics2['nodes'])
        node_similarity = min_nodes / max_nodes if max_nodes > 0 else 0
        similarities.append(node_similarity)
        
        max_edges = max(metrics1['edges'], metrics2['edges'])
        min_edges = min(metrics1['edges'], metrics2['edges'])
        edge_similarity = min_edges / max_edges if max_edges > 0 else 0
        similarities.append(edge_similarity)
        
        # 2. Entry point neighborhood comparison (high weight)
        entry_similarity = self._compare_entry_neighborhoods(graph1, graph2, entry1, entry2)
        similarities.append(entry_similarity)
        
        # 3. Path structure similarity from entry points
        path_similarity = self._compare_path_structures(graph1, graph2, entry1, entry2)
        similarities.append(path_similarity)
        
        # 4. Branch pattern similarity from entry points
        branch_similarity = self._compare_branch_patterns(graph1, graph2, entry1, entry2)
        similarities.append(branch_similarity)
        
        # 5. Overall connectivity pattern
        density_diff = abs(metrics1['density'] - metrics2['density'])
        density_similarity = 1.0 - min(density_diff, 1.0)
        similarities.append(density_similarity)
        
        # Weighted average with higher weights for pivot-based metrics
        weights = [0.10, 0.10, 0.35, 0.25, 0.15, 0.05]  # Entry neighborhood and path structure get highest weights
        weighted_similarity = sum(s * w for s, w in zip(similarities, weights))
        
        return weighted_similarity
    
    def _compare_entry_neighborhoods(self, graph1: nx.DiGraph, graph2: nx.DiGraph, entry1: str, entry2: str) -> float:
        """Compare the immediate neighborhoods of entry points"""
        # Get immediate successors and predecessors
        successors1 = set(graph1.successors(entry1))
        successors2 = set(graph2.successors(entry2))
        predecessors1 = set(graph1.predecessors(entry1))
        predecessors2 = set(graph2.predecessors(entry2))
        
        # Compare out-degree similarity
        out_degree1 = len(successors1)
        out_degree2 = len(successors2)
        max_out = max(out_degree1, out_degree2)
        min_out = min(out_degree1, out_degree2)
        out_degree_sim = min_out / max_out if max_out > 0 else 1.0
        
        # Compare in-degree similarity (entry points often have 0 predecessors)
        in_degree1 = len(predecessors1)
        in_degree2 = len(predecessors2)
        max_in = max(in_degree1, in_degree2)
        min_in = min(in_degree1, in_degree2)
        in_degree_sim = min_in / max_in if max_in > 0 else 1.0
        
        # Compare 2-hop neighborhoods
        two_hop1 = set()
        for succ in successors1:
            two_hop1.update(graph1.successors(succ))
        
        two_hop2 = set()
        for succ in successors2:
            two_hop2.update(graph2.successors(succ))
        
        two_hop_size1 = len(two_hop1)
        two_hop_size2 = len(two_hop2)
        max_two_hop = max(two_hop_size1, two_hop_size2)
        min_two_hop = min(two_hop_size1, two_hop_size2)
        two_hop_sim = min_two_hop / max_two_hop if max_two_hop > 0 else 1.0
        
        # Weighted combination
        return 0.4 * out_degree_sim + 0.2 * in_degree_sim + 0.4 * two_hop_sim
    
    def _compare_path_structures(self, graph1: nx.DiGraph, graph2: nx.DiGraph, entry1: str, entry2: str) -> float:
        """Compare path structures starting from entry points"""
        # Get path lengths from entry to all reachable nodes
        try:
            paths1 = nx.single_source_shortest_path_length(graph1, entry1, cutoff=5)
            paths2 = nx.single_source_shortest_path_length(graph2, entry2, cutoff=5)
        except nx.NetworkXError:
            return 0.0
        
        # Create distance histograms
        max_dist = max(max(paths1.values()) if paths1 else 0, max(paths2.values()) if paths2 else 0)
        if max_dist == 0:
            return 1.0
        
        hist1 = [0] * (max_dist + 1)
        hist2 = [0] * (max_dist + 1)
        
        for dist in paths1.values():
            hist1[dist] += 1
        for dist in paths2.values():
            hist2[dist] += 1
        
        # Normalize
        total1 = sum(hist1)
        total2 = sum(hist2)
        if total1 > 0:
            hist1 = [h / total1 for h in hist1]
        if total2 > 0:
            hist2 = [h / total2 for h in hist2]
        
        # Calculate intersection over union
        intersection = sum(min(h1, h2) for h1, h2 in zip(hist1, hist2))
        union = sum(max(h1, h2) for h1, h2 in zip(hist1, hist2))
        
        return intersection / union if union > 0 else 0.0
    
    def _compare_branch_patterns(self, graph1: nx.DiGraph, graph2: nx.DiGraph, entry1: str, entry2: str) -> float:
        """Compare branching patterns from entry points"""
        # Find all branching nodes (out-degree > 1) reachable from entry
        try:
            reachable1 = set(nx.descendants(graph1, entry1)) | {entry1}
            reachable2 = set(nx.descendants(graph2, entry2)) | {entry2}
        except nx.NetworkXError:
            return 0.0
        
        branch_nodes1 = [node for node in reachable1 if graph1.out_degree(node) > 1]
        branch_nodes2 = [node for node in reachable2 if graph2.out_degree(node) > 1]
        
        # Compare number of branching nodes
        max_branches = max(len(branch_nodes1), len(branch_nodes2))
        min_branches = min(len(branch_nodes1), len(branch_nodes2))
        branch_count_sim = min_branches / max_branches if max_branches > 0 else 1.0
        
        # Compare branching degrees
        branch_degrees1 = [graph1.out_degree(node) for node in branch_nodes1]
        branch_degrees2 = [graph2.out_degree(node) for node in branch_nodes2]
        
        if not branch_degrees1 and not branch_degrees2:
            degree_sim = 1.0
        elif not branch_degrees1 or not branch_degrees2:
            degree_sim = 0.0
        else:
            avg_degree1 = sum(branch_degrees1) / len(branch_degrees1)
            avg_degree2 = sum(branch_degrees2) / len(branch_degrees2)
            max_avg = max(avg_degree1, avg_degree2)
            min_avg = min(avg_degree1, avg_degree2)
            degree_sim = min_avg / max_avg if max_avg > 0 else 1.0
        
        return 0.6 * branch_count_sim + 0.4 * degree_sim


