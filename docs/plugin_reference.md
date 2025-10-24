# Plungin runs - Reference
1. windows.pslist - List of active processes and creation times (primary process inventory). We should aim for new processes in post-injection image, odd parent-child relationships.
2. windows.psscan - Find process structures in memory (to output hidden/terminated processes) i.e. suspect hidden/terminated processes.
##3. windows.netscan - Enumeration of network sockets and connections configs (local/remote IP:port, state, PID).
4. windows.cmdline - To show command line arguments used to start processes
5. windows.dlllist – list modules/DLLs loaded by processes.
6. windows.malfind - detect suspicious memory regions (potential code injections).