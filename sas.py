import re
import os
from collections import defaultdict
from datetime import datetime

def format_table_default(data_dict, section_title, sort_by_count=True, max_width=60):
    """
    Convert {name: [line_numbers]} into a simple text table (no external libs).
    """
    rows = []
    for name, lines in data_dict.items():
        if not isinstance(lines, list):
            lines = [lines]
        count = len(lines)
        line_str = ", ".join(map(str, lines))
        if len(line_str) > max_width:
            line_str = line_str[:max_width] + "..."
        rows.append((name, count, line_str))

    # Sort the rows either by count (descending) or alphabetically by name
    if sort_by_count:
        rows.sort(key=lambda x: x[1], reverse=True)
    else:
        rows.sort(key=lambda x: x[0].lower())

    # Determine column widths for alignment
    name_w = max((len(r[0]) for r in rows), default=4)
    count_w = max((len(str(r[1])) for r in rows), default=5)

    # Build header string with title and column names
    header = f"\n## {section_title} ({len(rows)})\n"
    header += f"{'Name'.ljust(name_w)}  {'Count'.rjust(count_w)}  Line Numbers\n"
    header += f"{'-'*name_w}  {'-'*count_w}  {'-'*max_width}\n"

    # Add each row formatted
    for name, count, line_str in rows:
        header += f"{name.ljust(name_w)}  {str(count).rjust(count_w)}  {line_str}\n"
    return header

def initialize_analysis():
    """
    Initialize and return the analysis results data structure.
    """
    results = {
        'function_blocks': [],
        'datasets_created': defaultdict(list),
        'datasets_used': defaultdict(list),
        'procedures_used': defaultdict(list),
        'macros_defined': defaultdict(dict),
        'macros_called': defaultdict(list),
        'libraries_defined': defaultdict(list),
        'sql_statements': defaultdict(list),
        'variables_used': defaultdict(list),
        'file_operations': defaultdict(list),
        'control_structures': defaultdict(list),
        'include_files': defaultdict(list),
        'system_functions': defaultdict(list),
        'call_routines': defaultdict(list),
        'formats': defaultdict(list),
        'hash_objects': defaultdict(list),
        'ods_statements': defaultdict(list),
        'jdbc_connections': defaultdict(list),  # New for JDBC connection lines
        'timeframe_start': None,
        'timeframe_end': None,
        'code_complexity': {},
        'line_analysis': {}
    }
    state = {
        'current_blocks': [],
        'include_stack': []
    }
    return results, state

def clean_line(line):
    """
    Remove block and line comments and convert to uppercase.
    """
    line = re.sub(r'/\*.*?\*/', '', line)  # Remove /* ... */ comments
    line = re.sub(r'^\s*\*.*$', '', line)  # Remove * comments
    return line.upper()

def classify_line(line):
    if re.match(r'^\s*%INCLUDE\s+', line):
        return 'INCLUDE'
    elif re.match(r'^\s*DATA\s+', line):
        return 'DATA_STEP'
    elif re.match(r'^\s*PROC\s+', line):
        return 'PROCEDURE'
    elif re.match(r'^\s*%MACRO\s+', line):
        return 'MACRO_DEF'
    elif re.match(r'^\s*%', line):
        return 'MACRO_CALL'
    elif re.match(r'^\s*LIBNAME\s+', line):
        return 'LIBRARY'
    elif re.match(r'^\s*ODS\s+', line):
        return 'ODS'
    elif 'RUN;' in line or 'QUIT;' in line:
        return 'TERMINATOR'
    else:
        return 'STATEMENT'

def analyze_include_files(line, line_num, results):
    include_pattern = re.compile(
        r'%INCLUDE\s*["\']([^"\']+)["\']|%INCLUDE\s*([^;]+);?',
        re.IGNORECASE
    )
    matches = include_pattern.findall(line)
    for quoted, unquoted in matches:
        filename = quoted if quoted else unquoted
        filename = filename.strip('"').strip("'").rstrip(';').strip()
        results['include_files'][filename].append(line_num)

def analyze_system_functions(line, line_num, results):
    sas_functions = [
        'SUM', 'MEAN', 'MIN', 'MAX', 'COUNT', 'N', 'NMISS',
        'SUBSTR', 'TRIM', 'STRIP', 'LEFT', 'RIGHT', 'LENGTH',
        'UPCASE', 'LOWCASE', 'PROPCASE', 'COMPRESS', 'TRANSLATE',
        'INDEX', 'FIND', 'SCAN', 'CATS', 'CATX', 'CAT',
        'INPUT', 'PUT', 'ROUND', 'CEIL', 'FLOOR', 'INT', 'ABS',
        'LOG', 'EXP', 'SQRT', 'SIN', 'COS', 'TAN',
        'TODAY', 'DATE', 'DATETIME', 'TIME', 'DATEPART', 'TIMEPART',
        'YEAR', 'MONTH', 'DAY', 'WEEKDAY', 'MDY', 'YMD',
        'INTCK', 'INTNX', 'DATDIF', 'JULDATE',
        'COALESCEC', 'COALESCE', 'IFC', 'IFN', 'MISSING',
        'RAND', 'RANUNI', 'NORMAL', 'GAMMA', 'BETA'
    ]
    for func in sas_functions:
        pattern = rf'\b{func}\s*\('
        if re.search(pattern, line):
            results['system_functions'][func].append(line_num)

def analyze_call_routines(line, line_num, results):
    call_routines = [
        'SYMPUT', 'SYMPUTX', 'SYMGET', 'SYMGETN',
        'EXECUTE', 'SYSTEM', 'FILENAME', 'LIBNAME',
        'STREAMINIT', 'RANUNI', 'RANTBL', 'VNAME',
        'LABEL', 'MISSING', 'SORTC', 'SORTN'
    ]
    for routine in call_routines:
        pattern = rf'\bCALL\s+{routine}\b'
        if re.search(pattern, line):
            results['call_routines'][f'CALL_{routine}'].append(line_num)

def analyze_formats(line, line_num, results):
    if re.search(r'\bPROC\s+FORMAT\b', line):
        results['formats']['PROC_FORMAT'].append(line_num)
    value_match = re.search(r'\bVALUE\s+([A-Z_][A-Z0-9_]*)', line)
    if value_match:
        results['formats'][f'VALUE_{value_match.group(1)}'].append(line_num)
    if re.search(r'\bINFORMAT\s+', line):
        results['formats']['INFORMAT'].append(line_num)

def analyze_hash_objects(line, line_num, results):
    hash_patterns = [
        ('DECLARE_HASH', r'DECLARE\s+HASH\s+([A-Z_][A-Z0-9_]*)'),
        ('DECLARE_HITER', r'DECLARE\s+HITER\s+([A-Z_][A-Z0-9_]*)'),
        ('DEFINEKEY', r'([A-Z_][A-Z0-9_]*)\.DEFINEKEY'),
        ('DEFINEDATA', r'([A-Z_][A-Z0-9_]*)\.DEFINEDATA'),
        ('DEFINEDONE', r'([A-Z_][A-Z0-9_]*)\.DEFINEDONE'),
        ('ADD', r'([A-Z_][A-Z0-9_]*)\.ADD'),
        ('FIND', r'([A-Z_][A-Z0-9_]*)\.FIND'),
        ('CHECK', r'([A-Z_][A-Z0-9_]*)\.CHECK')
    ]
    for operation, pattern in hash_patterns:
        matches = re.findall(pattern, line)
        for match in matches:
            results['hash_objects'][f'HASH_{operation}_{match}'].append(line_num)

def analyze_ods_statements(line, line_num, results):
    ods_operations = [
        'HTML', 'PDF', 'RTF', 'EXCEL', 'POWERPOINT', 'CSV',
        'LISTING', 'OUTPUT', 'TRACE', 'SELECT', 'EXCLUDE',
        'GRAPHICS', 'RESULTS', 'DESTINATIONS'
    ]
    for op in ods_operations:
        if re.search(rf'\bODS\s+{op}\b', line):
            results['ods_statements'][f'ODS_{op}'].append(line_num)

def check_block_start(line, line_num, results, state):
    data_match = re.match(r'^\s*DATA\s+([A-Z_][A-Z0-9_.]*(?:\s+[A-Z_][A-Z0-9_.]*)*)', line)
    if data_match:
        datasets = data_match.group(1).split()
        block_info = {
            'type': 'DATA',
            'name': f"DATA {' '.join(datasets)}",
            'start_line': line_num,
            'end_line': None,
            'datasets': datasets
        }
        state['current_blocks'].append(block_info)
        return
    proc_match = re.match(r'^\s*PROC\s+([A-Z]+)(?:\s+DATA\s*=\s*([A-Z_][A-Z0-9_.]*))?\s*;?', line)
    if proc_match:
        proc_name = proc_match.group(1)
        dataset = proc_match.group(2) if proc_match.group(2) else 'UNKNOWN'
        block_info = {
            'type': 'PROC',
            'name': f"PROC {proc_name}",
            'start_line': line_num,
            'end_line': None,
            'proc_name': proc_name,
            'dataset': dataset
        }
        state['current_blocks'].append(block_info)
        return
    macro_match = re.match(r'^\s*%MACRO\s+([A-Z_][A-Z0-9_]*)(\([^)]*\))?\s*;?', line)
    if macro_match:
        macro_name = macro_match.group(1)
        params = macro_match.group(2) if macro_match.group(2) else ''
        block_info = {
            'type': 'MACRO',
            'name': f"%MACRO {macro_name}",
            'start_line': line_num,
            'end_line': None,
            'macro_name': macro_name,
            'parameters': params
        }
        state['current_blocks'].append(block_info)

def check_block_end(line, line_num, results, state):
    if 'RUN;' in line or 'QUIT;' in line or '%MEND' in line:
        if state['current_blocks']:
            block = state['current_blocks'].pop()
            block['end_line'] = line_num
            results['function_blocks'].append(block)

def finalize_open_blocks(total_lines, results, state):
    while state['current_blocks']:
        block = state['current_blocks'].pop()
        block['end_line'] = total_lines
        results['function_blocks'].append(block)

def analyze_data_operations(line, line_num, results):
    data_match = re.search(r'DATA\s+([A-Z_][A-Z0-9_.]*(?:\s+[A-Z_][A-Z0-9_.]*)*)', line)
    if data_match:
        datasets = data_match.group(1).split()
        for dataset in datasets:
            results['datasets_created'][dataset].append(line_num)
    usage_patterns = [
        ('SET', r'SET\s+([A-Z_][A-Z0-9_.]*(?:\s+[A-Z_][A-Z0-9_.]*)*?)(?:\s|;|$)'),
        ('MERGE', r'MERGE\s+([A-Z_][A-Z0-9_.]*(?:\s+[A-Z_][A-Z0-9_.]*)*?)(?:\s|;|$)'),
        ('UPDATE', r'UPDATE\s+([A-Z_][A-Z0-9_.]*(?:\s+[A-Z_][A-Z0-9_.]*)*?)(?:\s|;|$)')
    ]
    for operation, pattern in usage_patterns:
        matches = re.findall(pattern, line)
        for match in matches:
            datasets = match.split()
            for dataset in datasets:
                results['datasets_used'][f"{operation}_{dataset}"].append(line_num)

def analyze_procedures(line, line_num, results):
    proc_match = re.search(r'PROC\s+([A-Z]+)(?:\s+DATA\s*=\s*([A-Z_][A-Z0-9_.]*))?\s*;?', line)
    if proc_match:
        proc_name = proc_match.group(1)
        dataset = proc_match.group(2) if proc_match.group(2) else 'UNKNOWN'
        results['procedures_used'][proc_name].append({
            'line': line_num,
            'dataset': dataset
        })

def analyze_macros(line, line_num, results):
    macro_def_match = re.search(r'%MACRO\s+([A-Z_][A-Z0-9_]*)(\([^)]*\))?\s*;?', line)
    if macro_def_match:
        macro_name = macro_def_match.group(1)
        params = macro_def_match.group(2) if macro_def_match.group(2) else ''
        results['macros_defined'][macro_name] = {
            'line': line_num,
            'parameters': params
        }
    macro_calls = re.findall(r'%([A-Z_][A-Z0-9_]*)\b', line)
    system_macros = {'MACRO', 'MEND', 'LET', 'IF', 'THEN', 'ELSE', 'DO', 'END','EVAL', 'STR', 'QUOTE', 'SCAN', 'SUBSTR', 'INCLUDE','ARRAY'}
    for macro_name in macro_calls:
        if macro_name not in system_macros:
            results['macros_called'][macro_name].append(line_num)

def analyze_sql_operations(line, line_num, results):
    sql_operations = [
        'SELECT', 'CREATE', 'INSERT', 'UPDATE', 'DELETE', 'ALTER', 'DROP',
        'FROM', 'WHERE', 'GROUP BY', 'HAVING', 'ORDER BY', 'UNION', 'JOIN'
    ]
    for operation in sql_operations:
        spaced_pattern = operation.replace(' ', r'\s+')
        word_boundary_pattern = rf'\b{spaced_pattern}\b'
        if re.search(word_boundary_pattern, line):
            operation_key = operation.replace(' ', '_')
            results['sql_statements'][operation_key].append(line_num)

def analyze_control_structures(line, line_num, results):
    control_patterns = [
        ('IF_THEN', r'\bIF\s+.*\bTHEN\b'),
        ('DO_LOOP', r'\bDO\b.*(?:TO|WHILE|UNTIL)'),
        ('ARRAY', r'\bARRAY\s+[A-Z_][A-Z0-9_]*'),
        ('FORMAT', r'\bFORMAT\s+'),
        ('LENGTH', r'\bLENGTH\s+'),
        ('LABEL', r'\bLABEL\s+'),
        ('RETAIN', r'\bRETAIN\s+'),
        ('OUTPUT', r'\bOUTPUT\s*;'),
        ('RETURN', r'\bRETURN\s*;'),
        ('DELETE', r'\bDELETE\s*;')
    ]
    for structure, pattern in control_patterns:
        if re.search(pattern, line):
            results['control_structures'][structure].append(line_num)

def analyze_file_operations(line, line_num, results):
    lib_match = re.search(r'LIBNAME\s+([A-Z_][A-Z0-9_]*)', line)
    if lib_match:
        lib_name = lib_match.group(1)
        results['libraries_defined'][lib_name].append(line_num)

    file_ops = [
        ('INFILE', r'\bINFILE\s+'),
        ('FILE', r'\bFILE\s+'),
        ('FILENAME', r'\bFILENAME\s+'),
        ('PUT', r'\bPUT\s+'),
        ('INPUT', r'\bINPUT\s+')
    ]
    for op_name, pattern in file_ops:
        if re.search(pattern, line):
            results['file_operations'][op_name].append(line_num)

def analyze_variables(line, line_num, results):
    var_ops = [
        ('KEEP', r'KEEP\s+([A-Z_][A-Z0-9_]*(?:\s+[A-Z_][A-Z0-9_]*)*?)(?:\s|;|$)'),
        ('DROP', r'DROP\s+([A-Z_][A-Z0-9_]*(?:\s+[A-Z_][A-Z0-9_]*)*?)(?:\s|;|$)'),
        ('VAR', r'VAR\s+([A-Z_][A-Z0-9_]*(?:\s+[A-Z_][A-Z0-9_]*)*?)(?:\s|;|$)'),
        ('BY', r'BY\s+([A-Z_][A-Z0-9_]*(?:\s+[A-Z_][A-Z0-9_]*)*?)(?:\s|;|$)'),
        ('CLASS', r'CLASS\s+([A-Z_][A-Z0-9_]*(?:\s+[A-Z_][A-Z0-9_]*)*?)(?:\s|;|$)')
    ]
    for op_name, pattern in var_ops:
        matches = re.findall(pattern, line)
        for match in matches:
            variables = match.split()
            for var in variables:
                results['variables_used'][f"{op_name}_{var}"].append(line_num)

def analyze_timeframes(line, line_num, results):
    timestamp_patterns = [
        r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}',
        r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}',
        r'\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}',
        r'\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2}'
    ]
    for pattern in timestamp_patterns:
        timestamps = re.findall(pattern, line)
        for timestamp in timestamps:
            if not results['timeframe_start']:
                results['timeframe_start'] = {'timestamp': timestamp, 'line': line_num}
            elif timestamp < results['timeframe_start']['timestamp']:
                results['timeframe_start'] = {'timestamp': timestamp, 'line': line_num}

            if not results['timeframe_end']:
                results['timeframe_end'] = {'timestamp': timestamp, 'line': line_num}
            elif timestamp > results['timeframe_end']['timestamp']:
                results['timeframe_end'] = {'timestamp': timestamp, 'line': line_num}

def calculate_complexity_metrics(results):
    total_functions = len(results['function_blocks'])
    total_datasets = len(results['datasets_created']) + len(results['datasets_used'])
    total_procedures = len(results['procedures_used'])
    total_macros = len(results['macros_defined'])
    total_includes = len(results['include_files'])
    total_sys_functions = len(results['system_functions'])
    total_jdbc_conns = len(results['jdbc_connections'])  # Count JDBC detections

    results['code_complexity'] = {
        'total_functions': total_functions,
        'total_datasets': total_datasets,
        'total_procedures': total_procedures,
        'total_macros': total_macros,
        'total_includes': total_includes,
        'total_sys_functions': total_sys_functions,
        'total_jdbc_connections': total_jdbc_conns,
        # Add JDBC to complexity score for awareness
        'complexity_score': total_functions + total_procedures + total_macros + total_includes + total_jdbc_conns,
        'total_lines': len(results['line_analysis'])
    }

def analyze_jdbc_connections(line, line_num, results):
    """
    Detect JDBC related connections or references including:
    - LIBNAME statements with JDBC
    - Comments or strings mentioning 'jdbc:' URLs or driver class names
    """
    # LIBNAME jdbc detection
    if re.search(r'LIBNAME\s+\w+\s+JDBC', line):
        # Extract LIBNAME and mark line
        libname_match = re.search(r'LIBNAME\s+(\w+)', line)
        libname = libname_match.group(1) if libname_match else "UNKNOWN_LIBNAME"
        results['jdbc_connections'][f"LIBNAME_{libname}"].append(line_num)

    # Detect URLs or connection strings containing 'jdbc:'
    jdbc_url_matches = re.findall(r'jdbc:[^\s\'";]+', line, flags=re.IGNORECASE)
    for url in jdbc_url_matches:
        results['jdbc_connections'][f"JDBC_URL_{url}"].append(line_num)

    # Detect common JDBC driver class references (Java style)
    jdbc_driver_matches = re.findall(r'com\.[a-zA-Z0-9_.]+driver', line, flags=re.IGNORECASE)
    for driver in jdbc_driver_matches:
        results['jdbc_connections'][f"JDBC_DRIVER_{driver}"].append(line_num)

def analyze_single_line(line, line_num, total_lines, source_file, results, state):
    original_line = line.strip()
    cleaned_line = clean_line(line).strip()
    if not cleaned_line:
        return

    results['line_analysis'][line_num] = {
        'original': original_line,
        'cleaned': cleaned_line,
        'type': classify_line(cleaned_line),
        'source_file': source_file
    }

    check_block_start(cleaned_line, line_num, results, state)

    analyze_data_operations(cleaned_line, line_num, results)
    analyze_procedures(cleaned_line, line_num, results)
    analyze_macros(cleaned_line, line_num, results)
    analyze_sql_operations(cleaned_line, line_num, results)
    analyze_control_structures(cleaned_line, line_num, results)
    analyze_file_operations(cleaned_line, line_num, results)
    analyze_variables(cleaned_line, line_num, results)
    analyze_include_files(cleaned_line, line_num, results)
    analyze_system_functions(cleaned_line, line_num, results)
    analyze_call_routines(cleaned_line, line_num, results)
    analyze_formats(cleaned_line, line_num, results)
    analyze_hash_objects(cleaned_line, line_num, results)
    analyze_ods_statements(cleaned_line, line_num, results)
    analyze_timeframes(original_line, line_num, results)

    # New: Analyze JDBC references
    analyze_jdbc_connections(line, line_num, results)

    check_block_end(cleaned_line, line_num, results, state)

def analyze_lines(lines, source_file=None):
    results, state = initialize_analysis()
    total_lines = len(lines)
    for line_num, line in enumerate(lines, 1):
        analyze_single_line(line, line_num, total_lines, source_file, results, state)
    finalize_open_blocks(total_lines, results, state)
    calculate_complexity_metrics(results)
    return results

def analyze_file(file_path):
    if not os.path.exists(file_path):
        print(f"❌ Error: File '{file_path}' not found.")
        return None

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        print(f"✅ Successfully loaded file: {file_path} ({len(lines)} lines)")
        return analyze_lines(lines, file_path)
    except Exception as e:
        print(f"❌ Error reading file {file_path}: {e}")
        return None

def generate_summary_report(results, source_file):
    if not results:
        return "❌ No analysis results available"

    complexity = results['code_complexity']

    report = f"""🔍 SAS CODE ANALYSIS SUMMARY REPORT
{'='*70}
📁 SOURCE FILE: {source_file}
📅 ANALYSIS DATE: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

📊 CODE METRICS:
   • Total Lines: {complexity['total_lines']}
   • Complexity Score: {complexity['complexity_score']}
   • Function Blocks: {complexity['total_functions']}
   • Procedures: {complexity['total_procedures']}
   • Macros: {complexity['total_macros']}
   • Include Files: {complexity['total_includes']}
   • System Functions: {complexity['total_sys_functions']}
   • JDBC Connections: {complexity.get('total_jdbc_connections', 0)}

📝 KEY COMPONENTS:
   • Datasets Created: {len(results['datasets_created'])}
   • Datasets Used: {len(results['datasets_used'])}
   • Libraries Defined: {len(results['libraries_defined'])}
   • SQL Statements: {len(results['sql_statements'])}
   • Control Structures: {len(results['control_structures'])}
   • CALL Routines: {len(results['call_routines'])}
   • Hash Objects: {len(results['hash_objects'])}
   • ODS Statements: {len(results['ods_statements'])}
"""
    if results['timeframe_start'] and results['timeframe_end']:
        report += f"""
⏰ EXECUTION TIMEFRAME:
   • Start: {results['timeframe_start']['timestamp']} (Line {results['timeframe_start']['line']})
   • End: {results['timeframe_end']['timestamp']} (Line {results['timeframe_end']['line']})
"""
    return report

def generate_detailed_report(results):
    if not results:
        return "❌ No analysis results available"

    source_file = results['line_analysis'].get(1, {}).get('source_file', '')

    report = generate_summary_report(results, source_file)

    function_blocks = [b for b in results['function_blocks'] if b.get('type') != 'MACRO']
    if function_blocks:
        report += "\n\n🔧 FUNCTION BLOCKS (Start → End Lines):\n"
        function_blocks.sort(key=lambda x: x['start_line'])
        for block in function_blocks:
            duration = block['end_line'] - block['start_line'] + 1
            report += f" • {block['name']}: Lines {block['start_line']} → {block['end_line']} ({duration} lines)\n"

    if results['include_files']:
        report += format_table_default(results['include_files'], "Include Files", sort_by_count=False)
    if results['system_functions']:
        report += format_table_default(results['system_functions'], "System Functions")
    if results['call_routines']:
        report += format_table_default(results['call_routines'], "CALL Routines")
    if results['hash_objects']:
        report += format_table_default(results['hash_objects'], "Hash Objects", sort_by_count=False)
    if results['ods_statements']:
        report += format_table_default(results['ods_statements'], "ODS Statements", sort_by_count=False)
    if results['formats']:
        report += format_table_default(results['formats'], "Formats", sort_by_count=False)
    if results['datasets_created']:
        report += format_table_default(results['datasets_created'], "Datasets Created")
    if results['datasets_used']:
        report += format_table_default(results['datasets_used'], "Datasets Used")

    if results['procedures_used']:
        proc_dict = {}
        for proc, instances in results['procedures_used'].items():
            lines = [f"{inst['line']} (data={inst['dataset']})" for inst in instances]
            proc_dict[proc] = lines
        report += format_table_default(proc_dict, "Procedures", sort_by_count=False)

    if results['macros_defined']:
        mdict = {f"%{name}{info['parameters']}": [info['line']] for name, info in results['macros_defined'].items()}
        report += format_table_default(mdict, "Macro Definitions", sort_by_count=False)

    if results['macros_called']:
        mcall_dict = {f"%{name}": lines for name, lines in results['macros_called'].items()}
        report += format_table_default(mcall_dict, "Macro Calls")

    if results['sql_statements']:
        report += format_table_default(results['sql_statements'], "SQL Operations")
    if results['control_structures']:
        report += format_table_default(results['control_structures'], "Control Structures")
    if results['libraries_defined']:
        report += format_table_default(results['libraries_defined'], "Libraries Defined", sort_by_count=False)
    if results['variables_used']:
        report += format_table_default(results['variables_used'], "Variable Operations")

    # New JDBC section in detailed report
    if results['jdbc_connections']:
        report += format_table_default(results['jdbc_connections'], "JDBC Connections", sort_by_count=False)

    return report

def save_reports(results, source_file, output_dir='reports'):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"✅ Created reports directory: {output_dir}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    detailed_report = generate_detailed_report(results)
    base_filename = os.path.splitext(os.path.basename(source_file))[0]
    detailed_filename = f"{output_dir}/{base_filename}_detailed_{timestamp}.txt"
    with open(detailed_filename, 'w', encoding='utf-8') as f:
        f.write(detailed_report)
    print(f"✅ Detailed report saved: {detailed_filename}")
    return detailed_filename

def analyze_sas_file(input_file_path, output_dir='reports', show_console_output=True):
    print("🚀 Starting SAS Code Analysis...")
    print("="*60)

    results = analyze_file(input_file_path)
    if not results:
        print("❌ Analysis failed")
        return None, None

    detailed_file = save_reports(results, input_file_path, output_dir)

    if show_console_output:
        print("\n" + "="*60)
        print("📊 CONSOLE OUTPUT - SUMMARY REPORT")
        print("="*60)
        print(generate_summary_report(results, input_file_path))

        print("\n" + "="*60)
        print("📋 CONSOLE OUTPUT - DETAILED REPORT")
        print("="*60)
        print(generate_detailed_report(results))

    print(f"\n✅ Analysis completed successfully!")
    print(f"📁 Reports saved in: {output_dir}/")
    return results, detailed_file

if __name__ == "__main__":
    print("🔍 SAS Code Analyzer")
    print("="*50)

    input_file = input("📁 Enter path to your SAS .txt file: ").strip()
    if not input_file:
        print("❌ No file specified. Exiting.")
        exit()

    if not os.path.exists(input_file):
        print(f"❌ File not found: {input_file}")
        exit()

    output_directory = input("📂 Enter reports output directory (press Enter for 'reports'): ").strip()
    if not output_directory:
        output_directory = 'reports'

    try:
        results, detailed_file = analyze_sas_file(
            input_file_path=input_file,
            output_dir=output_directory,
            show_console_output=True
        )
        print("\n🎉 Analysis Complete!")
        print(f"📊 Detailed Report: {detailed_file}")
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
