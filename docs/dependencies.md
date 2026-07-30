# Dependencies

Runtime dependencies are .NET 8/ASP.NET Core, Npgsql, PostgreSQL, SQLite for the Linux agent queue, and the .NET Model Context Protocol server library. Linux collection uses bounded platform facilities such as systemd journal and procfs according to the selected coverage tier.

Development scripts additionally use Bash, Python 3, `curl`, and PostgreSQL client tools. No browser runtime, frontend toolchain, embedded model client, OAuth library, remote-management library, or endpoint runtime for another operating system is required.

Dependencies must remain pinned through the existing .NET lock files and reviewed for license, provenance, maintenance, and security impact before introduction.
