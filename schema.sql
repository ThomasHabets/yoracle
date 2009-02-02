create table yubikey(
        yubikeyid char(12) not null,
        password varchar(40) not null,
        aeskey varchar(32) not null,
        counter int not null,
        counter_session int not null,
        secret_id char(12) not null,
        timestamp int not null,
        primary key(yubikeyid));
