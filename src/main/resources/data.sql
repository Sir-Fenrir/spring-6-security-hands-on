insert into users(username,password,enabled)
values ('world','$2a$10$TWL5MimaIorDkFRuqfyit.0TusTTk0HKbpuAgvNlSrH6a6MDj2Eka', true);

insert into users(username,password,enabled)
values ('universe','$2a$10$TWL5MimaIorDkFRuqfyit.0TusTTk0HKbpuAgvNlSrH6a6MDj2Eka', true);

insert into authorities(username, authority)
values ( 'world', 'ROLE_WORLD' );

insert into authorities(username, authority)
values ( 'universe', 'ROLE_UNIVERSE' );
