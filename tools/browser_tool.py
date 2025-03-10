from autogen.tools.experimental import BrowserUseTool

def create_browser_tool(llm_config, executor_agent, exploit_agents):
    """Creates and registers browser automation tools for web vulnerability testing
    using AG2's experimental browser tool capabilities"""
    
    # Initialize browser tool with experimental BrowserUseTool
    browser_tool = BrowserUseTool(
        llm_config=llm_config,
        browser_config={
            "headless": True,
            "ignore_https_errors": True,
            "viewport": {"width": 1280, "height": 1024}
        }
    )
    
    # Define custom browser actions for vulnerability testing
    browser_actions = {
        "test_xss": {
            "name": "test_xss",
            "description": "Test for XSS vulnerabilities in a web page element",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL of the page to test"
                    },
                    "selector": {
                        "type": "string",
                        "description": "CSS selector for the input element to test"
                    },
                    "payload": {
                        "type": "string",
                        "description": "XSS payload to inject"
                    }
                },
                "required": ["url", "selector", "payload"]
            }
        },
        "test_sql_injection": {
            "name": "test_sql_injection",
            "description": "Test for SQL injection vulnerabilities in a form",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL of the form to test"
                    },
                    "form_selector": {
                        "type": "string",
                        "description": "CSS selector for the form"
                    },
                    "input_selector": {
                        "type": "string",
                        "description": "CSS selector for the input element to inject payload"
                    },
                    "payload": {
                        "type": "string",
                        "description": "SQL injection payload to test"
                    },
                    "submit_selector": {
                        "type": "string",
                        "description": "CSS selector for the submit button"
                    }
                },
                "required": ["url", "form_selector", "input_selector", "payload", "submit_selector"]
            }
        }
    }
    
    # Implementation functions for custom actions
    async def test_xss_impl(page, url, selector, payload):
        """Implementation for XSS testing"""
        # Navigate to the URL
        await page.goto(url)
        
        # Wait for the selector to be available
        await page.wait_for_selector(selector)
        
        # Clear any existing value
        await page.evaluate(f'document.querySelector("{selector}").value = ""')
        
        # Type the XSS payload
        await page.type(selector, payload)
        
        # Find and click the closest form submit button
        script = """
        (selector) => {
            const element = document.querySelector(selector);
            const form = element.closest('form');
            if (form) {
                const submitButton = form.querySelector('button[type="submit"], input[type="submit"]');
                if (submitButton) submitButton.click();
            }
            return true;
        }
        """
        await page.evaluate(script, selector)
        
        # Wait for page to load after submission
        await page.wait_for_load_state("networkidle")
        
        # Check if the XSS payload executed
        check_script = f"""
        () => {{
            const alertCalled = window.__xssTestAlertCalled || false;
            return alertCalled;
        }}
        """
        
        # Get the page content to check for payload reflection
        content = await page.content()
        
        # Return the results
        result = {
            "url_tested": url,
            "payload_used": payload,
            "payload_reflected": payload in content,
            "page_content_sample": content[:500] + "..." if len(content) > 500 else content,
            "potential_vulnerability": payload in content
        }
        
        return result
    
    async def test_sql_injection_impl(page, url, form_selector, input_selector, payload, submit_selector):
        """Implementation for SQL injection testing"""
        # Navigate to the URL
        await page.goto(url)
        
        # Wait for the form to be available
        await page.wait_for_selector(form_selector)
        
        # Clear the input field
        await page.evaluate(f'document.querySelector("{input_selector}").value = ""')
        
        # Type the SQL injection payload
        await page.type(input_selector, payload)
        
        # Click the submit button
        await page.click(submit_selector)
        
        # Wait for page to load after submission
        await page.wait_for_load_state("networkidle")
        
        # Get the page content
        content = await page.content()
        
        # Check for common SQL error messages
        sql_errors = [
            "sql syntax", "syntax error", "mysql error", "oracle error",
            "sql server error", "postgresql error", "sqlite error",
            "unclosed quotation mark", "unterminated string"
        ]
        
        has_sql_error = any(error in content.lower() for error in sql_errors)
        
        # Return the results
        result = {
            "url_tested": url,
            "payload_used": payload,
            "sql_error_detected": has_sql_error,
            "page_content_sample": content[:500] + "..." if len(content) > 500 else content,
            "potential_vulnerability": has_sql_error
        }
        
        return result
    
    # Add custom actions to the browser tool
    browser_tool.add_action("test_xss", test_xss_impl)
    browser_tool.add_action("test_sql_injection", test_sql_injection_impl)
    
    # Register the browser tool with the executor agent for execution
    browser_tool.register_for_execution(executor_agent)
    
    # Register the browser tool with each exploitation agent for usage
    for agent in exploit_agents:
        browser_tool.register_for_llm(agent)
    
    return browser_tool