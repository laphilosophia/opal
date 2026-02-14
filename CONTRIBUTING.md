# Contributing to Crypthold

Thank you for your interest in contributing to Crypthold! We welcome contributions from the community to help make Crypthold even better.

## Development Workflow

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/crypthold.git
   cd crypthold
   ```
3. **Install dependencies**:
   ```bash
   npm install
   ```
4. **Create a new branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```
5. **Make your changes** and ensure tests pass:
   ```bash
   npm run build
   npm test
   ```
6. **Commit your changes** following [Conventional Commits](https://www.conventionalcommits.org/):
   ```bash
   git commit -m "feat: add support for custom encryption providers"
   ```
7. **Push to your fork** and **create a Pull Request**.

## Project Structure

- `src/`: Core logic and implementation.
- `tests/`: Unit and integration tests using Vitest.
- `examples/`: Demonstration scripts.
- `docs/`: Additional documentation.

## Coding Standards

- Use TypeScript for all new code.
- Ensure all public APIs are documented.
- Maintain the "hardened" and "atomic" guarantees of the project.
- Follow the existing linting and formatting rules.

## Reporting Issues

Use the GitHub [issue templates](.github/ISSUE_TEMPLATE/) to report bugs or suggest features. Provide as much detail as possible to help us triage and resolve the issue.
