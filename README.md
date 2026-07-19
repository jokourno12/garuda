# GARUDA
![image](https://img.shields.io/badge/powershell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)

![demo](src/Support/garuda-banner.gif)

Garuda is a high-performance, multithreaded network discovery platform engineered for cross-platform compatibility. By bypassing high-level abstractions in favor of direct socket-level primitives, Garuda minimizes runtime overhead and optimizes transport-layer interaction, delivering rapid, memory-efficient scanning across Windows, Linux, and macOS.

## Lean Development Principles
We ruthlessly eliminate waste to keep Garuda fast, lightweight, and rock-solid reliable. Rather than blindly adhering to a single execution model, we dynamically deploy the optimal tool—Synchronous or Asynchronous, Serial, Concurrent, or Parallel—tailored precisely to what each task requires:
- **Transportation**: Efficient data flow; passing object references instead of cloning data across execution and thread boundaries.
- **Inventory**: Lean codebase; minimal external dependencies with zero redundant modules or unused features.
- **Motion**: Direct execution via native .NET APIs to minimize unnecessary CPU context-switching and abstraction overhead.
- **Waiting**: Smart scheduling; utilizing Asynchronous non-blocking I/O for heavy tasks, yet safely pivoting to Synchronous execution when micro-tasks render async overhead wasteful.
- **Over Processing**: Tailored compute strategies; distributing workloads via multi-core Parallel execution for heavy computations, while enforcing strict Serial or Concurrent pipelines when absolute data consistency is mandatory.
- **Over Production**: Pure essentialism; building strictly what is necessary, completely eliminating architectural gold-plating and feature creep.
- **Defect**: Leak-free engineering; preventing race conditions and memory leaks by enforcing strict thread-safety and rigorous lifecycle management (Dispose) across all deployed execution models.
