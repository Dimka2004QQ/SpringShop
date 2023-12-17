INSERT INTO users (id, archive, email, name, password, role, bucket_id)
VALUES (1, false, 'mail@mail.ru', 'admin', '$2a$10$QRWAbXveneW1d.EKZPnxV.D7hjqPfw9Ex4nJuJpLgiFCDFopflogC', 'ADMIN',null);

ALTER SEQUENCE user_seq RESTART WITH 2;