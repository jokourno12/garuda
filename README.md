# GARUDA
![image](https://img.shields.io/badge/powershell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)

![demo](src/Support/garuda-banner.gif)

Garuda is a high-performance, multithreaded network discovery platform engineered for cross-platform compatibility. By bypassing high-level abstractions in favor of direct socket-level primitives, Garuda minimizes runtime overhead and optimizes transport-layer interaction, delivering rapid, memory-efficient scanning across Windows, Linux, and macOS.

## Lean Development Principles
We minimize waste to keep Garuda fast, lightweight, and reliable:
- **Transportation**: Efficient data flow; passing references instead of duplicating objects.
- **Inventory**: Lean codebase; minimizing dependencies and removing unused modules.
- **Motion**: Direct execution; using native .NET APIs to bypass abstraction overhead.
- **Waiting**: Asynchronous I/O; maximizing throughput by eliminating blocking operations.
- **Over Processing**: High-efficiency code; avoiding unnecessary wrapper cmdlets.
- **Over Production**: Essentialism; building only what is strictly necessary.
- **Defect**: Quality assurance; ensuring consistent, bug-free cross-platform execution.
