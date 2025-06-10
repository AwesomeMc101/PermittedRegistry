# PermittedRegistry
[tensora.xyz] Tool to monitor registry and give yourself options over process registry writing. 

# How it works
The tool injects a light DLL into every process running which hooks system registry functions.

When one of said functions is called, it presents a message box with information about the 
registry edit and asks the user if they want to allow it. If not, returns status failure.
