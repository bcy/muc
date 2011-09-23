Mu-conference can now write real time data in a MySQL database. This can be used to integrate mu-conference in a web page. For example it's easy to display the list of rooms in a webpage. Mu-conference still need a spool directory, the data stored in the database are just a copy of the current state of the rooms.

To create the database tables you can use the file mu-conference.sql.

This feature is disabled by default, to enable it, comment the second and fourth lines in src/Makefile, and uncomment the third and the fifth

Currently this only works with MySQL.
