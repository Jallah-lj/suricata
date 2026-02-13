# Contributing to Suricata IDS Documentation

Thank you for your interest in contributing to the Suricata IDS Documentation Repository! We welcome contributions from everyone, whether you're fixing a typo, adding new examples, or improving existing documentation.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Getting Started](#getting-started)
- [Contribution Guidelines](#contribution-guidelines)
- [Style Guidelines](#style-guidelines)
- [Submitting Changes](#submitting-changes)
- [Review Process](#review-process)

## 🤝 Code of Conduct

This project and everyone participating in it is governed by our commitment to fostering an open and welcoming environment. We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behavior includes:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behavior includes:**
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate in a professional setting

## 🎯 How Can I Contribute?

### Reporting Issues

If you find a bug, error, or have a suggestion:

1. **Check existing issues** to see if it's already reported
2. **Create a new issue** with a clear title and description
3. **Include examples** where applicable
4. **Specify the section** of documentation affected

### Suggesting Enhancements

We welcome suggestions for new documentation, examples, or improvements:

- Explain why this enhancement would be useful
- Provide examples of how it would work
- Consider if it fits the project's scope and audience

### Improving Documentation

Documentation improvements are always welcome:

- Fix typos, grammar, or formatting issues
- Clarify confusing sections
- Add missing information
- Update outdated content
- Improve code examples

### Adding Examples

New examples are valuable contributions:

- Detection rules for new attack types
- Configuration examples for different scenarios
- Analysis scripts for common tasks
- Real-world use cases

## 🚀 Getting Started

### Prerequisites

Before contributing, ensure you have:

- A GitHub account
- Git installed on your local machine
- Basic knowledge of Markdown
- Familiarity with Suricata (for technical contributions)

### Fork and Clone

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/suricata.git
   cd suricata
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Jallah-lj/suricata.git
   ```

### Create a Branch

Create a branch for your changes:

```bash
git checkout -b feature/your-feature-name
```

Use descriptive branch names:
- `docs/update-installation-guide`
- `rules/add-sqli-detection`
- `fix/correct-typos-in-config`
- `examples/add-malware-samples`

## 📝 Contribution Guidelines

### Documentation Contributions

When contributing to documentation:

1. **Be clear and concise** - Write for beginners while including advanced details
2. **Use proper formatting** - Follow Markdown best practices
3. **Include examples** - Every concept should have working examples
4. **Test commands** - Ensure all command examples actually work
5. **Cross-reference** - Link to related sections when appropriate
6. **Update ToC** - Update the table of contents if adding new sections

### Rule Contributions

When contributing detection rules:

1. **Test thoroughly** - Ensure rules work and don't produce false positives
2. **Comment clearly** - Explain what the rule detects and why
3. **Follow syntax** - Use proper Suricata rule syntax
4. **Provide context** - Include information about the threat being detected
5. **Include examples** - Show example traffic that would trigger the rule

### Script Contributions

When contributing scripts:

1. **Add comments** - Explain what the script does and how to use it
2. **Include usage examples** - Show how to run the script
3. **Handle errors** - Include proper error handling
4. **Make it portable** - Ensure it works across different systems
5. **Add dependencies** - Document any required libraries or tools

### Configuration Contributions

When contributing configuration files:

1. **Comment extensively** - Explain each section and setting
2. **Highlight important parts** - Mark sections that commonly need modification
3. **Provide defaults** - Include sensible default values
4. **Warn about risks** - Note settings that could impact security or performance

## 🎨 Style Guidelines

### Markdown Formatting

- Use `#` for headers (not underlines)
- Use backticks for `inline code`
- Use triple backticks for code blocks with language specification:
  ````markdown
  ```bash
  sudo suricata -i eth0
  ```
  ````
- Use **bold** for emphasis, *italic* for subtle emphasis
- Use tables for structured data
- Use numbered lists for sequential steps
- Use bullet lists for non-sequential items

### Code Style

**Shell Scripts:**
```bash
#!/bin/bash
# Script description
# Usage: ./script.sh [options]

set -e  # Exit on error

# Clear variable names
interface="eth0"

# Comment complex sections
# This checks if Suricata is installed
if command -v suricata &> /dev/null; then
    echo "Suricata is installed"
fi
```

**Python Scripts:**
```python
#!/usr/bin/env python3
"""
Script description

Usage:
    python script.py [options]
"""

import sys
import json

def main():
    """Main function with clear purpose"""
    # Implementation
    pass

if __name__ == "__main__":
    main()
```

**Suricata Rules:**
```
# Rule description: Detects SQL injection attempts
# Reference: CVE-XXXX or URL to documentation
alert http any any -> $HOME_NET any (msg:"SQL Injection Attempt"; \
    flow:established,to_server; \
    content:"UNION"; nocase; \
    pcre:"/union.+select/i"; \
    classtype:web-application-attack; \
    sid:1000001; rev:1;)
```

### Writing Style

- **Be clear and direct** - Avoid jargon when possible
- **Use active voice** - "Configure the interface" not "The interface should be configured"
- **Be specific** - Use concrete examples rather than abstract descriptions
- **Be inclusive** - Write for diverse skill levels
- **Be accurate** - Double-check technical information
- **Be consistent** - Use consistent terminology throughout

### Command Examples

Always provide complete, runnable commands:

```bash
# Good: Complete, copy-pasteable command
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Bad: Incomplete or placeholder
suricata -i <interface>
```

Include expected output when helpful:

```bash
$ suricata --build-info
This is Suricata version 6.0.0
Features: AF_PACKET HAVE_PACKET_FANOUT...
```

## 📤 Submitting Changes

### Before Submitting

1. **Test your changes** - Ensure everything works
2. **Review your changes** - Check for typos and formatting
3. **Update documentation** - If you changed structure
4. **Commit logically** - Make atomic commits with clear messages

### Commit Messages

Write clear, descriptive commit messages:

```
Add SQL injection detection rules

- Added 5 new rules for common SQLi patterns
- Included examples and testing guidance
- Updated rules/README.md with usage information
```

Format:
- First line: Brief summary (50 chars or less)
- Blank line
- Detailed description with bullet points
- Reference issues: "Fixes #123" or "Relates to #456"

### Creating a Pull Request

1. **Push your branch** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub

3. **Fill out the PR template** with:
   - Clear description of changes
   - Why the change is needed
   - How to test the changes
   - Screenshots (if applicable)
   - Related issues

4. **Request review** from maintainers

### PR Best Practices

- **Keep PRs focused** - One feature or fix per PR
- **Keep PRs small** - Easier to review and merge
- **Update your PR** - Address review comments promptly
- **Rebase if needed** - Keep commit history clean
- **Be patient** - Reviews take time

## 🔍 Review Process

### What to Expect

1. **Initial review** - A maintainer will review your PR within a few days
2. **Feedback** - You may receive comments or change requests
3. **Discussion** - We may discuss the best approach
4. **Approval** - Once approved, your PR will be merged
5. **Credit** - You'll be credited as a contributor

### Review Criteria

Reviewers will check for:

- **Correctness** - Information is accurate
- **Clarity** - Documentation is easy to understand
- **Completeness** - All necessary information is included
- **Consistency** - Follows existing style and structure
- **Quality** - Examples work and are well-explained
- **Security** - No security issues introduced

## 🏆 Recognition

Contributors are recognized in several ways:

- Listed in the project's contributors
- Mentioned in release notes
- Credited in relevant documentation sections

## ❓ Questions?

If you have questions about contributing:

- Open an issue with the "question" label
- Check existing issues and documentation
- Reach out to maintainers

## 📚 Additional Resources

- [Markdown Guide](https://www.markdownguide.org/)
- [Git Documentation](https://git-scm.com/doc)
- [Suricata Documentation](https://suricata.readthedocs.io/)
- [GitHub Flow Guide](https://guides.github.com/introduction/flow/)

---

Thank you for contributing to making Suricata more accessible to everyone! 🎉
