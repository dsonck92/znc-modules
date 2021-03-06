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
* `SetQuery [query]` : Sets the query to use to check for authentication, use ? for replacing data. If the query returns a 'realname' column, it will set the realname of the user.
* `SetQueryArgs [arg1] [arg2] ...` : Sets the mapping of ? to values. Use {password} and {user} for password and user values respectively.
* `GetQuery` : Prints the active query
* `LoadNetworkMods` : Which network modules to load automatically
* `LoadUserMods` : Which user modules to load automatically
* `UserMods` : Shows the network + user modules that are loaded automatically
* `SetNetworks [net "server" ...] | ...` : a pipe delimited list of network definitions as 'netname "server1" "..."'
* `Networks` : Show the configured networks

### Example:

```
status> loadmod mysqlauth localhost znc znc_secret znc
mysqlauth> setquery SELECT `display_name` AS realname FROM `wp_users` WHERE `user_nicename` = ? AND `user_pass` = SHA2(?,256)
mysqlauth> setqueryargs {user} {password}
```

### Compiling:

To compile, you need the mysql-connector-cpp library, after instaling:

```
LIBS=-lmysqlcppconn znc-buildmod mysqlauth.cpp
```

And copy the generated `mysqlauth.so` to `~/.znc/modules/`
