# Dependencies

Runtime dependencies are .NET 8/ASP.NET Core, Npgsql, PostgreSQL, SQLite for the Linux agent queue and optional private geolocation cache, and the .NET Model Context Protocol server library. The optional traffic interface uses pinned React 19, TypeScript, Vite, Leaflet, and React Leaflet packages; its production JavaScript and CSS are self-hosted by ASP.NET Core. Linux collection uses bounded platform facilities such as systemd journal and procfs according to the selected coverage tier. The separately approved Linux x86_64 kernel-network helper additionally requires cgroup v2, kernel BTF, dynamic `libbpf.so.1`, libelf, and zlib at runtime; Clang/LLVM and a C linker are build-host dependencies only, never endpoint runtime compilers.

Development scripts additionally use Bash, Python 3, `curl`, PostgreSQL client tools, and Node.js/npm only when building or testing the optional interface. No browser runtime is required for backend-only operation; no embedded model client, OAuth library, remote-management library, or endpoint runtime for another operating system is present.

Dependencies must remain pinned through the existing .NET lock files and reviewed for license, provenance, maintenance, and security impact before introduction.
