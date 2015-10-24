# znc-modules
Various ZNC modules


## mysqlauth.cpp

A module which allows a custom MySQL query as authentication method. Optionally it can Create and Clone an user account if no account exists. Allows custom networks and modules to be configured on creation. Automatically loads NickServ with the supplied password for nickserv authentication.

### Commands:

* `AutoClearChanBuffer [yes|no]` : Whether newly created users should have auto clear channel buffers
* `CloneUser [user]` : Sets the user to clone if no configured user matches
* `CreateUser [yes|no]` : Whether the plugin should create a user when no configured user matches
* `DenyLoadMod [yes|no]` : Whether newly created users are allowed to load modules
* `DisableCloneUser` : Unsets the clone user
* `SetQuery [query]` : Sets the query to use to check for authentication, $u$ is replaced by user, $p$ is replaced by password. When the query returns at least 1 result, the authentication passes. If the query returns a 'realname' column, it will set the realname of the user.
* `GetQuery` : Prints the active query
* `LoadNetworkMods` : Which network modules to load automatically
* `LoadUserMods` : Which user modules to load automatically
* `UserMods` : Shows the network + user modules that are loaded automatically
* `SetNetworks [net "server" ...] | ...` : a pipe delimited list of network definitions as 'netname "server1" "..."'
* `Networks` : Show the configured networks
